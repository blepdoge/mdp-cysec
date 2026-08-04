package hashing

import (
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
	"strings"
	"sync"
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

	// Step 1: Gather all files
	type fileEntry struct {
		path string
		info fs.FileInfo
	}

	var files []fileEntry

	err := filepath.WalkDir(h.RootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.Type().IsRegular() {
			info, err := d.Info()
			if err == nil {
				files = append(files, fileEntry{path, info})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	totalFiles := len(files)
	if progressChan != nil {
		progressChan <- ProgressUpdate{Total: totalFiles, Processed: 0}
	}

	if totalFiles == 0 {
		now := time.Now().UTC()
		manifest.CaseMetadata = models.CaseMetadata{
			ManifestVersion:   "1.0",
			TotalArtifacts:    0,
			EvidenceDirectory: h.RootDir,
			SnapshotDirectory: h.SnapshotDir,
			CreationTimestamp: &now,
		}
		if progressChan != nil {
			close(progressChan)
		}
		return manifest, nil
	}

	// Step 2: Set up worker pool
	numWorkers := runtime.NumCPU() * 2
	bufferSize := totalFiles
	if bufferSize > 10000 {
		bufferSize = 10000
	}
	jobs := make(chan fileEntry, bufferSize)
	resultsChan := make(chan models.Artifact, bufferSize)

	var artifacts []models.Artifact
	var collectorWg sync.WaitGroup

	// Background collector
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for art := range resultsChan {
			artifacts = append(artifacts, art)
			if progressChan != nil {
				progressChan <- ProgressUpdate{Total: totalFiles, Processed: len(artifacts)}
			}
		}
	}()

	var wg sync.WaitGroup

	// Launch workers
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range jobs {
				if art, err := hashFile(h.RootDir, h.SnapshotDir, entry.path, entry.info); err == nil {
					resultsChan <- art
				}
			}
		}()
	}

	// Feed jobs
	for _, entry := range files {
		jobs <- entry
	}
	close(jobs)

	// Wait for workers to finish
	wg.Wait()
	close(resultsChan)
	// Wait for collector to finish
	collectorWg.Wait()

	if progressChan != nil {
		close(progressChan)
	}

	// The worker pool collects artifacts in nondeterministic order. A canonical
	// ordering is required so the manifest (and the Merkle root derived from it)
	// is reproducible across runs. Sort by name, with path as tie-breaker since
	// names are not unique.
	slices.SortFunc(artifacts, func(a, b models.Artifact) int {
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Path, b.Path)
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

// use 4mB buffer instead of default 32kb one, improve large file performance
var bufPool = sync.Pool{
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

	buf := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)

	relPath, err := filepath.Rel(rootDir, filePath)
	if err != nil {
		return models.Artifact{}, err
	}
	relPath = filepath.ToSlash(relPath)

	var snapshotTemp *os.File
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
	}

	writer := io.MultiWriter(hs.md5, hs.sha1, hs.sha256)
	if snapshotTemp != nil {
		writer = io.MultiWriter(hs.md5, hs.sha1, hs.sha256, snapshotTemp)
	}
	if _, err := io.CopyBuffer(writer, f, *buf); err != nil {
		if snapshotTemp != nil {
			_ = os.Remove(snapshotTemp.Name())
		}
		return models.Artifact{}, err
	}

	artifactSHA256 := hex.EncodeToString(hs.sha256.Sum(nil))
	artifactSHA1 := hex.EncodeToString(hs.sha1.Sum(nil))
	artifactMD5 := hex.EncodeToString(hs.md5.Sum(nil))

	artifact := models.Artifact{
		Name:      info.Name(),
		Path:      "/" + relPath,
		SizeBytes: info.Size(),
		SHA256:    artifactSHA256,
		SHA1:      artifactSHA1,
		MD5:       artifactMD5,
	}

	if snapshotTemp != nil {
		if err := snapshotTemp.Close(); err != nil {
			_ = os.Remove(snapshotTemp.Name())
			return models.Artifact{}, err
		}

		pathHash := sha256.Sum256([]byte(relPath))
		snapshotName := fmt.Sprintf("%s_%x.snapshot", artifactSHA256, pathHash[:8])
		finalPath := filepath.Join(snapshotDir, snapshotName)
		if err := os.Rename(snapshotTemp.Name(), finalPath); err != nil {
			_ = os.Remove(snapshotTemp.Name())
			return models.Artifact{}, err
		}
		artifact.BaselineSnapshotPath = snapshotName
	}

	return artifact, nil
}
