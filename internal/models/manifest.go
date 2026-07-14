package models

import (
	"encoding/json"
	"os"
	"time"
)

type CaseMetadata struct {
	CaseRootHash      string     `json:"case_root_hash"`
	TotalArtifacts    int        `json:"total_artifacts"`
	CreationTimestamp *time.Time `json:"creation_timestamp,omitempty"`
	RFC3161TokenPath  string     `json:"rfc3161_token_path,omitempty"`
	EvidenceDirectory string     `json:"evidence_directory,omitempty"`
}

type Artifact struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	SHA1   string `json:"sha1"`
	MD5    string `json:"md5"`
}

type MasterManifest struct {
	CaseMetadata CaseMetadata `json:"case_metadata"`
	Artifacts    []Artifact   `json:"artifacts"`
}

// SaveToFile serializes the manifest to JSON and writes it to the specified path.
func (m *MasterManifest) SaveToFile(path string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
