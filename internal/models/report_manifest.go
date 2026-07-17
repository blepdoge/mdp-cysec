package models

import (
	"encoding/json"
	"os"
	"time"
)

type ExportMetadata struct {
	ExportTimestamp string `json:"export_timestamp"`
	TotalExhibits   int    `json:"total_exhibits"`
}

type ReportExhibit struct {
	OriginalPath      string `json:"original_path"`
	ExhibitName       string `json:"exhibit_name"`
	SourceSHA256      string `json:"source_sha256"`
	IntegrityVerified bool   `json:"integrity_verified"`
}

type ReportManifest struct {
	ExportMetadata ExportMetadata  `json:"export_metadata"`
	Exhibits       []ReportExhibit `json:"exhibits"`
}

func NewReportManifest() *ReportManifest {
	return &ReportManifest{
		ExportMetadata: ExportMetadata{
			ExportTimestamp: time.Now().UTC().Format(time.RFC3339),
			TotalExhibits:   0,
		},
		Exhibits: make([]ReportExhibit, 0),
	}
}

func (m *ReportManifest) SaveToFile(path string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
