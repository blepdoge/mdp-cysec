package exporting

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"mdp-cysec/internal/models"
)

type QuoteResult struct {
	OriginalPath      string `json:"original_path"`
	ExhibitName       string `json:"exhibit_name"`
	SourceSHA256      string `json:"source_sha256"`
	IntegrityVerified bool   `json:"integrity_verified"`
	CopiedPath        string `json:"copied_path"`
	ManifestPath      string `json:"manifest_path"`
}

func QuoteArtifact(rootDir, originalPath, exportDirectory string, manifest *models.MasterManifest) (*QuoteResult, error) {
	if manifest == nil {
		return nil, fmt.Errorf("no manifest loaded")
	}

	art, ok := findArtifact(manifest, originalPath)
	if !ok {
		return nil, fmt.Errorf("artifact not found: %s", originalPath)
	}

	sourcePath, err := resolveSourcePath(rootDir, art.Path)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(exportDirectory, 0755); err != nil {
		return nil, err
	}
	if err := ensureWritableDirectory(exportDirectory); err != nil {
		return nil, err
	}

	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return nil, err
	}
	defer sourceFile.Close()

	sourceName := filepath.Base(sourcePath)
	prefix := art.SHA256
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	exhibitName := fmt.Sprintf("%s_%s", prefix, sourceName)
	copiedPath := filepath.Join(exportDirectory, exhibitName)

	destFile, err := os.Create(copiedPath)
	if err != nil {
		return nil, err
	}
	defer destFile.Close()

	hashWriter := sha256.New()
	multiWriter := io.MultiWriter(destFile, hashWriter)
	if _, err := io.Copy(multiWriter, sourceFile); err != nil {
		return nil, err
	}

	computedSHA := hex.EncodeToString(hashWriter.Sum(nil))
	integrityVerified := strings.EqualFold(computedSHA, art.SHA256)

	if err := updateReportManifest(exportDirectory, models.ReportExhibit{
		OriginalPath:      art.Path,
		ExhibitName:       exhibitName,
		SourceSHA256:      art.SHA256,
		IntegrityVerified: integrityVerified,
	}); err != nil {
		return nil, err
	}

	if !integrityVerified {
		return nil, fmt.Errorf("integrity verification failed: source hash %s does not match copied hash %s", art.SHA256, computedSHA)
	}

	manifestPath := filepath.Join(exportDirectory, "report_manifest.json")
	return &QuoteResult{
		OriginalPath:      art.Path,
		ExhibitName:       exhibitName,
		SourceSHA256:      art.SHA256,
		IntegrityVerified: integrityVerified,
		CopiedPath:        copiedPath,
		ManifestPath:      manifestPath,
	}, nil
}

func QuoteArtifactsBulk(rootDir string, originalPaths []string, exportDirectory string, manifest *models.MasterManifest) ([]*QuoteResult, error) {
	if manifest == nil {
		return nil, fmt.Errorf("no manifest loaded")
	}
	if len(originalPaths) == 0 {
		return nil, fmt.Errorf("no artifact paths provided for bulk quote")
	}

	if err := os.MkdirAll(exportDirectory, 0755); err != nil {
		return nil, err
	}
	if err := ensureWritableDirectory(exportDirectory); err != nil {
		return nil, err
	}

	results := make([]*QuoteResult, 0, len(originalPaths))
	exhibitsToUpsert := make([]models.ReportExhibit, 0, len(originalPaths))

	for _, origPath := range originalPaths {
		art, ok := findArtifact(manifest, origPath)
		if !ok {
			return nil, fmt.Errorf("artifact not found: %s", origPath)
		}

		sourcePath, err := resolveSourcePath(rootDir, art.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve path for %s: %w", art.Path, err)
		}

		sourceFile, err := os.Open(sourcePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open file %s: %w", sourcePath, err)
		}

		sourceName := filepath.Base(sourcePath)
		prefix := art.SHA256
		if len(prefix) > 8 {
			prefix = prefix[:8]
		}
		exhibitName := fmt.Sprintf("%s_%s", prefix, sourceName)
		copiedPath := filepath.Join(exportDirectory, exhibitName)

		destFile, err := os.Create(copiedPath)
		if err != nil {
			sourceFile.Close()
			return nil, fmt.Errorf("failed to create destination file %s: %w", copiedPath, err)
		}

		hashWriter := sha256.New()
		multiWriter := io.MultiWriter(destFile, hashWriter)
		_, copyErr := io.Copy(multiWriter, sourceFile)
		sourceFile.Close()
		destFile.Close()
		if copyErr != nil {
			return nil, fmt.Errorf("failed to copy file %s: %w", sourcePath, copyErr)
		}

		computedSHA := hex.EncodeToString(hashWriter.Sum(nil))
		integrityVerified := strings.EqualFold(computedSHA, art.SHA256)
		if !integrityVerified {
			return nil, fmt.Errorf("integrity verification failed for %s: expected %s, got %s", art.Path, art.SHA256, computedSHA)
		}

		exhibitsToUpsert = append(exhibitsToUpsert, models.ReportExhibit{
			OriginalPath:      art.Path,
			ExhibitName:       exhibitName,
			SourceSHA256:      art.SHA256,
			IntegrityVerified: integrityVerified,
		})

		manifestPath := filepath.Join(exportDirectory, "report_manifest.json")
		results = append(results, &QuoteResult{
			OriginalPath:      art.Path,
			ExhibitName:       exhibitName,
			SourceSHA256:      art.SHA256,
			IntegrityVerified: integrityVerified,
			CopiedPath:        copiedPath,
			ManifestPath:      manifestPath,
		})
	}

	manifestPath := filepath.Join(exportDirectory, "report_manifest.json")
	reportManifest := models.NewReportManifest()
	if existing, err := os.ReadFile(manifestPath); err == nil {
		_ = json.Unmarshal(existing, reportManifest)
	}

	for _, ex := range exhibitsToUpsert {
		upsertExhibit(reportManifest, ex)
	}
	reportManifest.ExportMetadata.ExportTimestamp = time.Now().UTC().Format(time.RFC3339)
	reportManifest.ExportMetadata.TotalExhibits = len(reportManifest.Exhibits)

	if err := reportManifest.SaveToFile(manifestPath); err != nil {
		return nil, fmt.Errorf("failed to save report manifest: %w", err)
	}

	return results, nil
}

func findArtifact(manifest *models.MasterManifest, originalPath string) (models.Artifact, bool) {
	for _, art := range manifest.Artifacts {
		if art.Path == originalPath || art.Name == filepath.Base(originalPath) {
			return art, true
		}
	}
	return models.Artifact{}, false
}

func resolveSourcePath(rootDir, artifactPath string) (string, error) {
	if artifactPath == "" {
		return "", fmt.Errorf("original path is empty")
	}

	cleaned := filepath.Clean(artifactPath)
	if _, err := os.Stat(cleaned); err == nil {
		return cleaned, nil
	}

	if rootDir == "" {
		return "", fmt.Errorf("evidence root directory is not configured")
	}

	trimmed := strings.TrimPrefix(strings.TrimPrefix(cleaned, "/"), `\`)
	if trimmed == "." {
		trimmed = ""
	}
	sourcePath := filepath.Join(rootDir, trimmed)
	return sourcePath, nil
}

func updateReportManifest(exportDirectory string, exhibit models.ReportExhibit) error {
	manifestPath := filepath.Join(exportDirectory, "report_manifest.json")

	reportManifest := models.NewReportManifest()
	if existing, err := os.ReadFile(manifestPath); err == nil {
		_ = json.Unmarshal(existing, reportManifest)
	}

	upsertExhibit(reportManifest, exhibit)
	reportManifest.ExportMetadata.ExportTimestamp = time.Now().UTC().Format(time.RFC3339)
	reportManifest.ExportMetadata.TotalExhibits = len(reportManifest.Exhibits)

	return reportManifest.SaveToFile(manifestPath)
}

func ensureWritableDirectory(exportDirectory string) error {
	testFile, err := os.CreateTemp(exportDirectory, ".write-check-*")
	if err != nil {
		return fmt.Errorf("export directory is not writable: %w", err)
	}
	name := testFile.Name()
	testFile.Close()
	return os.Remove(name)
}

func upsertExhibit(reportManifest *models.ReportManifest, exhibit models.ReportExhibit) {
	for i := range reportManifest.Exhibits {
		if reportManifest.Exhibits[i].OriginalPath == exhibit.OriginalPath {
			reportManifest.Exhibits[i] = exhibit
			return
		}
	}
	reportManifest.Exhibits = append(reportManifest.Exhibits, exhibit)
}

func DeleteQuotedArtifact(exportDirectory, originalPath, exhibitName, copiedPath string) error {
	if exportDirectory == "" && copiedPath != "" {
		exportDirectory = filepath.Dir(copiedPath)
	}
	if exportDirectory == "" {
		return fmt.Errorf("export directory is required")
	}

	manifestPath := filepath.Join(exportDirectory, "report_manifest.json")
	if existing, err := os.ReadFile(manifestPath); err == nil {
		reportManifest := models.NewReportManifest()
		if err := json.Unmarshal(existing, reportManifest); err == nil {
			newExhibits := make([]models.ReportExhibit, 0, len(reportManifest.Exhibits))
			for _, ex := range reportManifest.Exhibits {
				if (originalPath != "" && ex.OriginalPath == originalPath) ||
					(exhibitName != "" && ex.ExhibitName == exhibitName) {
					continue
				}
				newExhibits = append(newExhibits, ex)
			}
			reportManifest.Exhibits = newExhibits
			reportManifest.ExportMetadata.TotalExhibits = len(newExhibits)
			reportManifest.ExportMetadata.ExportTimestamp = time.Now().UTC().Format(time.RFC3339)
			_ = reportManifest.SaveToFile(manifestPath)
		}
	}

	targetFile := copiedPath
	if targetFile == "" && exhibitName != "" {
		targetFile = filepath.Join(exportDirectory, exhibitName)
	}
	if targetFile != "" {
		if err := os.Remove(targetFile); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete exhibit file copy: %w", err)
		}
	}

	return nil
}
