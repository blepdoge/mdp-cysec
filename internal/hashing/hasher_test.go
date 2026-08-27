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

func TestGenerateManifestProgressUpdates(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 20; i++ {
		writeFile(t, root, filepath.Join("subdir", "file_"+string(rune('a'+i))+".txt"), "content")
	}

	progressChan := make(chan ProgressUpdate, 100)
	var updates []ProgressUpdate

	done := make(chan struct{})
	go func() {
		for u := range progressChan {
			updates = append(updates, u)
		}
		close(done)
	}()

	manifest, err := NewHasher(root).GenerateManifest(progressChan)
	if err != nil {
		t.Fatalf("GenerateManifest failed: %v", err)
	}
	<-done

	if manifest.CaseMetadata.TotalArtifacts != 20 {
		t.Fatalf("TotalArtifacts = %d, want 20", manifest.CaseMetadata.TotalArtifacts)
	}
	if len(updates) == 0 {
		t.Fatal("expected at least one progress update")
	}
	last := updates[len(updates)-1]
	if last.Processed != 20 || last.Total != 20 {
		t.Errorf("last update = %+v, want Processed=20, Total=20", last)
	}
}

func BenchmarkHasherSmallFiles(b *testing.B) {
	root := b.TempDir()
	content := []byte("hello world small file content benchmarking test")
	for i := 0; i < 500; i++ {
		path := filepath.Join(root, "sub", "file_"+string(rune('a'+(i%26)))+"_"+string(rune('0'+(i%10)))+".txt")
		_ = os.MkdirAll(filepath.Dir(path), 0755)
		_ = os.WriteFile(path, content, 0644)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := NewHasher(root).GenerateManifest(nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHasherLargeFileThroughput(b *testing.B) {
	root := b.TempDir()
	fileSize := int64(20 * 1024 * 1024) // 20 MB
	f, err := os.Create(filepath.Join(root, "large.bin"))
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 1024*1024)
	for i := 0; i < 20; i++ {
		_, _ = f.Write(buf)
	}
	_ = f.Close()

	b.SetBytes(fileSize)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := NewHasher(root).GenerateManifest(nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

