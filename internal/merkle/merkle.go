// Package merkle implements a binary Merkle tree over the SHA256 hashes of
// case artifacts, producing a single root hash that commits to the entire
// evidence set (issue #3).
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"mdp-cysec/internal/models"
)

// Tree is a binary Merkle tree. Levels[0] holds the leaf hashes in manifest
// order; each subsequent level holds the parent hashes, up to the last level
// which contains only the root.
type Tree struct {
	Levels [][][]byte
}

// New builds a Merkle tree from the given leaf hashes. When a level contains
// an odd number of nodes, the last node is duplicated and hashed against
// itself, as done in Bitcoin. A single leaf is its own root. Returns an error
// if no leaves are provided.
func New(leaves [][]byte) (*Tree, error) {
	if len(leaves) == 0 {
		return nil, errors.New("merkle: cannot build a tree without leaves")
	}

	levels := [][][]byte{leaves}
	for current := leaves; len(current) > 1; {
		next := make([][]byte, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			left := current[i]
			right := left
			if i+1 < len(current) {
				right = current[i+1]
			}
			next = append(next, hashPair(left, right))
		}
		levels = append(levels, next)
		current = next
	}

	return &Tree{Levels: levels}, nil
}

// FromManifest builds the tree using the SHA256 hash of every artifact in the
// manifest as leaves, in manifest order. The manifest must therefore already
// be in canonical order for the root to be reproducible.
func FromManifest(m *models.MasterManifest) (*Tree, error) {
	leaves := make([][]byte, 0, len(m.Artifacts))
	for _, art := range m.Artifacts {
		leaf, err := hex.DecodeString(art.SHA256)
		if err != nil {
			return nil, fmt.Errorf("merkle: invalid SHA256 for %s: %w", art.Path, err)
		}
		leaves = append(leaves, leaf)
	}
	return New(leaves)
}

// Root returns the root hash of the tree.
func (t *Tree) Root() []byte {
	top := t.Levels[len(t.Levels)-1]
	return top[0]
}

// RootHex returns the root hash as a lowercase hex string.
func (t *Tree) RootHex() string {
	return hex.EncodeToString(t.Root())
}

// hashPair returns the SHA256 hash of the concatenation of two child nodes.
func hashPair(left, right []byte) []byte {
	buf := make([]byte, 0, len(left)+len(right))
	buf = append(buf, left...)
	buf = append(buf, right...)
	sum := sha256.Sum256(buf)
	return sum[:]
}
