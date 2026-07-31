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
				SHA256:    "69800ff8e515d9a941584c017d2a58b88d8b9d5c48b0662d5d8525b6a713ef33",
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
				SHA256:    "08e7a08b5be4c70d49f059a4b86c382b6b060d4b9681121d58cfb96b349d592b", // sha256 of "hello 1"
				SizeBytes: int64(len(content1)),
			},
			{
				Name:      "file2.txt",
				Path:      file2,
				SHA256:    "e6f53a48e89ebf9f59f63cf6efd1b82e21b764619d08e5e89a54483788a8eb68", // sha256 of "hello 2"
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
