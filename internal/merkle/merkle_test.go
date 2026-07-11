package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"mdp-cysec/internal/models"
)

// leaf derives a deterministic fake leaf hash from a label.
func leaf(label string) []byte {
	sum := sha256.Sum256([]byte(label))
	return sum[:]
}

// pair hashes the concatenation of two nodes, mirroring the tree rule.
func pair(left, right []byte) []byte {
	sum := sha256.Sum256(append(append([]byte{}, left...), right...))
	return sum[:]
}

func TestNewEvenLeaves(t *testing.T) {
	a, b, c, d := leaf("a"), leaf("b"), leaf("c"), leaf("d")
	tree, err := New([][]byte{a, b, c, d})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	want := pair(pair(a, b), pair(c, d))
	if !bytes.Equal(tree.Root(), want) {
		t.Errorf("root = %x, want %x", tree.Root(), want)
	}
	if len(tree.Levels) != 3 {
		t.Errorf("levels = %d, want 3", len(tree.Levels))
	}
}

func TestNewOddLeavesDuplicatesLast(t *testing.T) {
	a, b, c := leaf("a"), leaf("b"), leaf("c")
	tree, err := New([][]byte{a, b, c})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}

	// Bitcoin-style: the odd last node is hashed against itself.
	want := pair(pair(a, b), pair(c, c))
	if !bytes.Equal(tree.Root(), want) {
		t.Errorf("root = %x, want %x", tree.Root(), want)
	}
}

func TestNewSingleLeafIsRoot(t *testing.T) {
	a := leaf("a")
	tree, err := New([][]byte{a})
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if !bytes.Equal(tree.Root(), a) {
		t.Errorf("root = %x, want the leaf itself %x", tree.Root(), a)
	}
}

func TestNewNoLeaves(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("expected error for empty leaves, got nil")
	}
}

func TestDeterminism(t *testing.T) {
	leaves := [][]byte{leaf("a"), leaf("b"), leaf("c"), leaf("d"), leaf("e")}
	t1, err := New(leaves)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	t2, err := New(leaves)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	if t1.RootHex() != t2.RootHex() {
		t.Errorf("same leaves produced different roots: %s vs %s", t1.RootHex(), t2.RootHex())
	}
}

func TestFromManifest(t *testing.T) {
	a, b := leaf("a"), leaf("b")
	m := &models.MasterManifest{
		Artifacts: []models.Artifact{
			{Name: "a.txt", Path: "/a.txt", SHA256: hex.EncodeToString(a)},
			{Name: "b.txt", Path: "/b.txt", SHA256: hex.EncodeToString(b)},
		},
	}

	tree, err := FromManifest(m)
	if err != nil {
		t.Fatalf("FromManifest returned error: %v", err)
	}
	if want := pair(a, b); !bytes.Equal(tree.Root(), want) {
		t.Errorf("root = %x, want %x", tree.Root(), want)
	}
}

func TestFromManifestInvalidHex(t *testing.T) {
	m := &models.MasterManifest{
		Artifacts: []models.Artifact{
			{Name: "bad.txt", Path: "/bad.txt", SHA256: "not-hex"},
		},
	}
	if _, err := FromManifest(m); err == nil {
		t.Error("expected error for invalid hex, got nil")
	}
}
