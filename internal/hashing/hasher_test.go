package hashing

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// writeFile creates a file with parents under root or fails the test.
func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}
}

func TestGenerateManifestCanonicalOrder(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "b/common.txt", "b-common")
	writeFile(t, root, "a/common.txt", "a-common")
	writeFile(t, root, "delta.txt", "delta")
	writeFile(t, root, "alpha.txt", "alpha")

	manifest, err := NewHasher(root).GenerateManifest(nil)
	if err != nil {
		t.Fatalf("GenerateManifest returned error: %v", err)
	}
	if manifest.CaseMetadata.TotalArtifacts != 4 {
		t.Fatalf("total artifacts = %d, want 4", manifest.CaseMetadata.TotalArtifacts)
	}

	// Sorted by name, path as tie-breaker for the duplicate common.txt.
	wantPaths := []string{"/alpha.txt", "/a/common.txt", "/b/common.txt", "/delta.txt"}
	for i, want := range wantPaths {
		if got := manifest.Artifacts[i].Path; got != want {
			t.Errorf("artifact[%d].Path = %q, want %q", i, got, want)
		}
	}
}

func TestGenerateManifestHashes(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "alpha.txt", "alpha")

	manifest, err := NewHasher(root).GenerateManifest(nil)
	if err != nil {
		t.Fatalf("GenerateManifest returned error: %v", err)
	}
	if len(manifest.Artifacts) != 1 {
		t.Fatalf("artifacts = %d, want 1", len(manifest.Artifacts))
	}

	sum := sha256.Sum256([]byte("alpha"))
	if got, want := manifest.Artifacts[0].SHA256, hex.EncodeToString(sum[:]); got != want {
		t.Errorf("SHA256 = %s, want %s", got, want)
	}
}

func TestGenerateManifestEmptyDir(t *testing.T) {
	manifest, err := NewHasher(t.TempDir()).GenerateManifest(nil)
	if err != nil {
		t.Fatalf("GenerateManifest returned error: %v", err)
	}
	if manifest.CaseMetadata.TotalArtifacts != 0 {
		t.Errorf("total artifacts = %d, want 0", manifest.CaseMetadata.TotalArtifacts)
	}
}

func TestGenerateManifestStoresSnapshots(t *testing.T) {
	root := t.TempDir()
	snapshotDir := filepath.Join(t.TempDir(), "snapshots")
	writeFile(t, root, "alpha.txt", "alpha")

	manifest, err := NewHasher(root, snapshotDir).GenerateManifest(nil)
	if err != nil {
		t.Fatalf("GenerateManifest returned error: %v", err)
	}
	if len(manifest.Artifacts) != 1 {
		t.Fatalf("artifacts = %d, want 1", len(manifest.Artifacts))
	}

	artifact := manifest.Artifacts[0]
	if artifact.BaselineSnapshotPath == "" {
		t.Fatal("expected baseline snapshot path to be recorded")
	}

	snapshotPath := filepath.Join(snapshotDir, artifact.BaselineSnapshotPath)
	if _, err := os.Stat(snapshotPath); err != nil {
		t.Fatalf("expected snapshot file at %s: %v", snapshotPath, err)
	}
	if manifest.CaseMetadata.SnapshotDirectory != snapshotDir {
		t.Fatalf("snapshot directory = %q, want %q", manifest.CaseMetadata.SnapshotDirectory, snapshotDir)
	}
}
