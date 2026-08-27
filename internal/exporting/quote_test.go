package exporting

import (
	"os"
	"path/filepath"
	"testing"

	"mdp-cysec/internal/models"
)

func TestQuoteAndDeleteArtifact(t *testing.T) {
	tempDir := t.TempDir()
	sourceFile := filepath.Join(tempDir, "sample.txt")
	content := []byte("hello evidence world")
	if err := os.WriteFile(sourceFile, content, 0644); err != nil {
		t.Fatalf("failed to create source file: %v", err)
	}

	manifest := &models.MasterManifest{
		Artifacts: []models.Artifact{
			{
				Name:      "sample.txt",
				Path:      sourceFile,
				SHA256:    "019b2f52bca72502e01475c0c13d352b3dbf8139a4b9f378b37443ee218d7e5b",
				SizeBytes: int64(len(content)),
			},
		},
	}

	exportDir := filepath.Join(tempDir, "export")

	result, err := QuoteArtifact(tempDir, sourceFile, exportDir, manifest)
	if err != nil {
		t.Fatalf("QuoteArtifact failed: %v", err)
	}

	if _, err := os.Stat(result.CopiedPath); os.IsNotExist(err) {
		t.Fatalf("expected copied file at %s, but not found", result.CopiedPath)
	}

	manifestFile := filepath.Join(exportDir, "report_manifest.json")
	if _, err := os.Stat(manifestFile); os.IsNotExist(err) {
		t.Fatalf("expected report manifest at %s, but not found", manifestFile)
	}

	// Now test DeleteQuotedArtifact
	if err := DeleteQuotedArtifact(exportDir, result.OriginalPath, result.ExhibitName, result.CopiedPath); err != nil {
		t.Fatalf("DeleteQuotedArtifact failed: %v", err)
	}

	// Verify copied file was deleted
	if _, err := os.Stat(result.CopiedPath); !os.IsNotExist(err) {
		t.Fatalf("expected copied file %s to be deleted, but it still exists", result.CopiedPath)
	}
}

func TestQuoteArtifactsBulk(t *testing.T) {
	tempDir := t.TempDir()

	file1 := filepath.Join(tempDir, "file1.txt")
	content1 := []byte("hello 1")
	_ = os.WriteFile(file1, content1, 0644)

	file2 := filepath.Join(tempDir, "file2.txt")
	content2 := []byte("hello 2")
	_ = os.WriteFile(file2, content2, 0644)

	manifest := &models.MasterManifest{
		Artifacts: []models.Artifact{
			{
				Name:      "file1.txt",
				Path:      file1,
				SHA256:    "50db240d003e4fa4832a8e5f5b38d51f260a68f6337c0c16f960c4ccfb1ac028", // sha256 of "hello 1"
				SizeBytes: int64(len(content1)),
			},
			{
				Name:      "file2.txt",
				Path:      file2,
				SHA256:    "bf949020174558630551a377686f51a7cd4519be43f3514f3bdfc205ee558e6a", // sha256 of "hello 2"
				SizeBytes: int64(len(content2)),
			},
		},
	}

	exportDir := filepath.Join(tempDir, "bulk_export")
	results, err := QuoteArtifactsBulk(tempDir, []string{file1, file2}, exportDir, manifest)
	if err != nil {
		t.Fatalf("QuoteArtifactsBulk failed: %v", err)
	}

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	for _, res := range results {
		if _, err := os.Stat(res.CopiedPath); os.IsNotExist(err) {
			t.Fatalf("expected copied file at %s, but not found", res.CopiedPath)
		}
	}
}
