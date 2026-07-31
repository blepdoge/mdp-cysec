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
