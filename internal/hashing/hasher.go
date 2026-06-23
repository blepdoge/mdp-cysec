package hashing

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/user/mdp-cysec/internal/models"
)

type Hasher struct {
	RootDir string
}

func NewHasher(rootDir string) *Hasher {
	return &Hasher{RootDir: rootDir}
}

// GenerateManifest walks the root directory and creates the manifest.
// The progressChan can be used to send updates (e.g. number of files processed) back to the caller.
func (h *Hasher) GenerateManifest(progressChan chan<- int) (*models.MasterManifest, error) {
	manifest := &models.MasterManifest{
		Artifacts: make([]models.Artifact, 0),
	}

	var artifacts []models.Artifact
	var mu sync.Mutex
	var wg sync.WaitGroup

	err := filepath.Walk(h.RootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err // Ignore permission errors or handle? We return for now.
		}
		if info.IsDir() {
			return nil
		}

		wg.Add(1)
		go func(filePath string, fileInfo os.FileInfo) {
			defer wg.Done()

			art, hashErr := hashFile(h.RootDir, filePath, fileInfo)
			if hashErr != nil {
				// We skip files we can't read
				return
			}

			mu.Lock()
			artifacts = append(artifacts, art)
			if progressChan != nil {
				progressChan <- len(artifacts)
			}
			mu.Unlock()

		}(path, info)

		return nil
	})

	if err != nil {
		return nil, err
	}

	wg.Wait()
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
