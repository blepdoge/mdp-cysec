package hashing

import (
	"bufio"
	"cmp"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"mdp-cysec/internal/models"
)

type Hasher struct {
	RootDir     string
	SnapshotDir string
}

// NewHasher creates and returns a new Hasher instance with the given RootDir.
func NewHasher(rootDir string, snapshotDir ...string) *Hasher {
	h := &Hasher{RootDir: rootDir}
	if len(snapshotDir) > 0 {
		h.SnapshotDir = snapshotDir[0]
	}
	return h
}

type ProgressUpdate struct {
	Total     int
	Processed int
}

// GenerateManifest walks the root directory and creates the manifest.
// The progressChan can be used to send updates (e.g. number of files processed) back to the caller.
func (h *Hasher) GenerateManifest(progressChan chan<- ProgressUpdate) (*models.MasterManifest, error) {
	manifest := &models.MasterManifest{
		Artifacts: make([]models.Artifact, 0),
	}

	if h.SnapshotDir != "" {
		if err := os.MkdirAll(h.SnapshotDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create snapshot directory: %w", err)
		}
	}

	type fileEntry struct {
		path string
		info fs.FileInfo
	}

	numWorkers := runtime.NumCPU() * 2
	if numWorkers < 4 {
		numWorkers = 4
	}

	// Buffered channels to decouple directory walk from worker consumption
	jobs := make(chan fileEntry, 1024)
	resultsChan := make(chan models.Artifact, 1024)

	var discoveredFiles atomic.Int64
	var artifacts []models.Artifact
	var collectorWg sync.WaitGroup

	// Background collector
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for art := range resultsChan {
			artifacts = append(artifacts, art)
			if progressChan != nil {
				progressChan <- ProgressUpdate{
					Total:     int(discoveredFiles.Load()),
					Processed: len(artifacts),
				}
			}
		}
	}()

	var workerWg sync.WaitGroup
	// Launch workers
	for w := 0; w < numWorkers; w++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for entry := range jobs {
				if art, err := hashFile(h.RootDir, h.SnapshotDir, entry.path, entry.info); err == nil {
					resultsChan <- art
				}
			}
		}()
	}

	// Pipelined directory walking directly into jobs channel
	walkErr := filepath.WalkDir(h.RootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				discoveredFiles.Add(1)
				jobs <- fileEntry{path: path, info: info}
			}
		}
		return nil
	})

	close(jobs)
	workerWg.Wait()
	close(resultsChan)
	collectorWg.Wait()

	if progressChan != nil {
		close(progressChan)
	}

	if walkErr != nil && len(artifacts) == 0 {
		return nil, walkErr
	}

	// The worker pool collects artifacts in nondeterministic order. A canonical
	// ordering is required so the manifest (and the Merkle root derived from it)
	// is reproducible across runs. Sort by name, with path as tie-breaker since
	// names are not unique.
	slices.SortFunc(artifacts, func(a, b models.Artifact) int {
		if c := cmp.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return cmp.Compare(a.Path, b.Path)
	})

	now := time.Now().UTC()

	var totalBytes int64
	for _, art := range artifacts {
		totalBytes += art.SizeBytes
	}

	manifest.Artifacts = artifacts
	manifest.CaseMetadata = models.CaseMetadata{
		ManifestVersion:   "1.0",
		TotalArtifacts:    len(artifacts),
		TotalBytes:        totalBytes,
		EvidenceDirectory: h.RootDir,
		SnapshotDirectory: h.SnapshotDir,
		CreationTimestamp: &now,
	}

	return manifest, nil
}

type hashers struct {
	md5    hash.Hash
	sha1   hash.Hash
	sha256 hash.Hash
}

var hashersPool = sync.Pool{
	New: func() interface{} {
		return &hashers{
			md5:    md5.New(),
			sha1:   sha1.New(),
			sha256: sha256.New(),
		}
	},
}

// Adaptive buffer pools: 64KB for small files (reduces memory & cache thrashing), 4MB for large files.
var smallBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 64*1024) // 64KB
		return &buf
	},
}

var largeBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 4*1024*1024) // 4MB
		return &buf
	},
}

// hashFile opens a file, computes its SHA256, SHA1, and MD5 hashes in a single pass,
// and optionally stores a baseline snapshot that can be used later for diffing.
func hashFile(rootDir, snapshotDir, filePath string, info os.FileInfo) (models.Artifact, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return models.Artifact{}, err
	}
	defer f.Close()

	hs := hashersPool.Get().(*hashers)
	defer func() {
		hs.md5.Reset()
		hs.sha1.Reset()
		hs.sha256.Reset()
		hashersPool.Put(hs)
	}()

	var buf *[]byte
	if info.Size() <= 64*1024 {
		buf = smallBufPool.Get().(*[]byte)
		defer smallBufPool.Put(buf)
	} else {
		buf = largeBufPool.Get().(*[]byte)
		defer largeBufPool.Put(buf)
	}

	relPath, err := filepath.Rel(rootDir, filePath)
	if err != nil {
		return models.Artifact{}, err
	}
	relPath = filepath.ToSlash(relPath)

	var snapshotTemp *os.File
	var snapshotBufWriter *bufio.Writer
	if snapshotDir != "" {
		snapshotTemp, err = os.CreateTemp(snapshotDir, ".baseline-*")
		if err != nil {
			return models.Artifact{}, err
		}
		defer func() {
			if snapshotTemp != nil {
				snapshotTemp.Close()
			}
		}()
		snapshotBufWriter = bufio.NewWriterSize(snapshotTemp, 256*1024)
	}

	var writer io.Writer
	if snapshotBufWriter != nil {
		writer = io.MultiWriter(hs.md5, hs.sha1, hs.sha256, snapshotBufWriter)
	} else {
		writer = io.MultiWriter(hs.md5, hs.sha1, hs.sha256)
	}

	if _, err := io.CopyBuffer(writer, f, *buf); err != nil {
		if snapshotTemp != nil {
			_ = os.Remove(snapshotTemp.Name())
		}
		return models.Artifact{}, err
	}

	if snapshotBufWriter != nil {
		if err := snapshotBufWriter.Flush(); err != nil {
			_ = os.Remove(snapshotTemp.Name())
			return models.Artifact{}, err
		}
	}

	var sha256Buf [32]byte
	var sha1Buf [20]byte
	var md5Buf [16]byte

	artifactSHA256 := hex.EncodeToString(hs.sha256.Sum(sha256Buf[:0]))
	artifactSHA1 := hex.EncodeToString(hs.sha1.Sum(sha1Buf[:0]))
	artifactMD5 := hex.EncodeToString(hs.md5.Sum(md5Buf[:0]))

	artifact := models.Artifact{
		Name:      info.Name(),
		Path:      "/" + relPath,
		SizeBytes: info.Size(),
		SHA256:    artifactSHA256,
		SHA1:      artifactSHA1,
		MD5:       artifactMD5,
	}

	if snapshotTemp != nil {
		tempName := snapshotTemp.Name()
		if err := snapshotTemp.Close(); err != nil {
			_ = os.Remove(tempName)
			return models.Artifact{}, err
		}
		snapshotTemp = nil

		pathHash := sha256.Sum256([]byte(relPath))
		snapshotName := fmt.Sprintf("%s_%x.snapshot", artifactSHA256, pathHash[:8])
		finalPath := filepath.Join(snapshotDir, snapshotName)
		if err := os.Rename(tempName, finalPath); err != nil {
			_ = os.Remove(tempName)
			return models.Artifact{}, err
		}
		artifact.BaselineSnapshotPath = snapshotName
	}

	return artifact, nil
}
