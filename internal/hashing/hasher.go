package hashing

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"mdp-cysec/internal/models"
)

type Hasher struct {
	RootDir string
}

// NewHasher creates and returns a new Hasher instance with the given RootDir.
func NewHasher(rootDir string) *Hasher {
	return &Hasher{RootDir: rootDir}
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

	// Step 1: Gather all files
	var files []string
	err := filepath.WalkDir(h.RootDir, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return nil // ignore errors like permissions for now
		}
		if info.Type().IsRegular() {
			files = append(files, path)
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
			SourcePath:        h.RootDir,
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
	jobs := make(chan string, bufferSize)
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
			for path := range jobs {
				// We need info for the artifact name
				info, err := os.Stat(path)
				if err != nil {
					continue
				}
				if art, err := hashFile(h.RootDir, path, info); err == nil {
					resultsChan <- art
				}
			}
		}()
	}

	// Feed jobs
	for _, path := range files {
		jobs <- path
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

	now := time.Now().UTC()
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].Path < artifacts[j].Path
	})

	var totalBytes int64
	for _, art := range artifacts {
		totalBytes += art.SizeBytes
	}

	manifest.Artifacts = artifacts
	manifest.CaseMetadata = models.CaseMetadata{
		ManifestVersion:   "1.0",
		TotalArtifacts:    len(artifacts),
		TotalBytes:        totalBytes,
		SourcePath:        h.RootDir,
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

// hashFile opens a file, computes its SHA256, SHA1, and MD5 hashes in a single pass,
// and returns a models.Artifact struct with the calculated hashes and relative path.
func hashFile(rootDir, filePath string, info os.FileInfo) (models.Artifact, error) {
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

	writer := io.MultiWriter(hs.md5, hs.sha1, hs.sha256)
	if _, err := io.Copy(writer, f); err != nil {
		return models.Artifact{}, err
	}

	relPath, err := filepath.Rel(rootDir, filePath)
	if err != nil {
		return models.Artifact{}, err
	}
	relPath = filepath.ToSlash(relPath)
	return models.Artifact{
		Name:         info.Name(),
		Path:         "/" + relPath,
		SizeBytes:    info.Size(),
		SHA256:       hex.EncodeToString(hs.sha256.Sum(nil)),
		SHA1:         hex.EncodeToString(hs.sha1.Sum(nil)),
		MD5:          hex.EncodeToString(hs.md5.Sum(nil)),
	}, nil
}

