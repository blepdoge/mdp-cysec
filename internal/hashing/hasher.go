package hashing

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
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

// GenerateManifest walks the root directory and creates the manifest.
// The progressChan can be used to send updates (e.g. number of files processed) back to the caller.
func (h *Hasher) GenerateManifest(progressChan chan<- int) (*models.MasterManifest, error) {
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
	if totalFiles == 0 {
		now := time.Now().UTC()
		manifest.CaseMetadata = models.CaseMetadata{
			TotalArtifacts:    0,
			CreationTimestamp: &now,
		}
		if progressChan != nil {
			close(progressChan)
		}
		return manifest, nil
	}

	// Step 2: Set up worker pool
	numWorkers := runtime.NumCPU() * 2
	jobs := make(chan string, totalFiles)
	resultsChan := make(chan models.Artifact, totalFiles)

	var artifacts []models.Artifact
	var collectorWg sync.WaitGroup

	// Background collector
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for art := range resultsChan {
			artifacts = append(artifacts, art)
			if progressChan != nil {
				progressChan <- len(artifacts)
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
	manifest.Artifacts = artifacts
	manifest.CaseMetadata = models.CaseMetadata{
		TotalArtifacts:    len(artifacts),
		CreationTimestamp: &now,
	}

	return manifest, nil
}

// hashFile opens a file, computes its SHA256, SHA1, and MD5 hashes in a single pass,
// and returns a models.Artifact struct with the calculated hashes and relative path.
func hashFile(rootDir, filePath string, info os.FileInfo) (models.Artifact, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return models.Artifact{}, err
	}
	defer f.Close()

	hashMD5 := md5.New()
	hashSHA1 := sha1.New()
	hashSHA256 := sha256.New()

	writer := io.MultiWriter(hashMD5, hashSHA1, hashSHA256)
	if _, err := io.Copy(writer, f); err != nil {
		return models.Artifact{}, err
	}

	relPath, err := filepath.Rel(rootDir, filePath)
	if err != nil {
		return models.Artifact{}, err
	}
	relPath = filepath.ToSlash(relPath)

	return models.Artifact{
		Name:   info.Name(),
		Path:   "/" + relPath,
		SHA256: hex.EncodeToString(hashSHA256.Sum(nil)),
		SHA1:   hex.EncodeToString(hashSHA1.Sum(nil)),
		MD5:    hex.EncodeToString(hashMD5.Sum(nil)),
	}, nil
}
