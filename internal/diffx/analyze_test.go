package diffx

import (
	"os"
	"path/filepath"
	"testing"

	"mdp-cysec/internal/models"
)

func TestAnalyzeChangeText(t *testing.T) {
	root := t.TempDir()
	snapshotDir := filepath.Join(root, "snapshots")
	if err := os.MkdirAll(snapshotDir, 0755); err != nil {
		t.Fatalf("mkdir snapshot dir: %v", err)
	}

	snapshotName := "baseline.snapshot"
	if err := os.WriteFile(filepath.Join(snapshotDir, snapshotName), []byte("line one\nline two\nline three\n"), 0644); err != nil {
		t.Fatalf("write baseline snapshot: %v", err)
	}
	currentPath := filepath.Join(root, "current.txt")
	if err := os.WriteFile(currentPath, []byte("line one\nline 2 changed\nline three\n"), 0644); err != nil {
		t.Fatalf("write current file: %v", err)
	}

	analysis, err := AnalyzeChange(models.Artifact{
		Path:                 "/current.txt",
		BaselineSnapshotPath: snapshotName,
	}, currentPath, snapshotDir)
	if err != nil {
		t.Fatalf("AnalyzeChange returned error: %v", err)
	}
	if analysis.Kind != "text" {
		t.Fatalf("kind = %q, want text", analysis.Kind)
	}
	if analysis.Text == nil || len(analysis.Text.Operations) == 0 {
		t.Fatal("expected text operations to be populated")
	}
}

func TestAnalyzeChangeBinary(t *testing.T) {
	root := t.TempDir()
	snapshotDir := filepath.Join(root, "snapshots")
	if err := os.MkdirAll(snapshotDir, 0755); err != nil {
		t.Fatalf("mkdir snapshot dir: %v", err)
	}

	snapshotName := "baseline.snapshot"
	if err := os.WriteFile(filepath.Join(snapshotDir, snapshotName), []byte{0x00, 0x01, 0x02, 0x03}, 0644); err != nil {
		t.Fatalf("write baseline snapshot: %v", err)
	}
	currentPath := filepath.Join(root, "current.bin")
	if err := os.WriteFile(currentPath, []byte{0x00, 0x01, 0xFF, 0x03}, 0644); err != nil {
		t.Fatalf("write current file: %v", err)
	}

	analysis, err := AnalyzeChange(models.Artifact{
		Path:                 "/current.bin",
		BaselineSnapshotPath: snapshotName,
	}, currentPath, snapshotDir)
	if err != nil {
		t.Fatalf("AnalyzeChange returned error: %v", err)
	}
	if analysis.Kind != "binary" {
		t.Fatalf("kind = %q, want binary", analysis.Kind)
	}
	if analysis.Binary == nil || analysis.Binary.DifferingByteCount == 0 {
		t.Fatal("expected binary diff details to be populated")
	}
}
