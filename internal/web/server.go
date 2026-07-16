package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"mdp-cysec/internal/hashing"
	"mdp-cysec/internal/models"
)

type Server struct {
	mux             *http.ServeMux
	templates       *template.Template
	rootDir         string
	
	clients         map[chan string]bool
	clientsMu       sync.Mutex
	currentManifest *models.MasterManifest
	currentRootDir  string
	lastVerification *VerificationResult

	// Thread-safe state tracking for hashing progress
	stateMu         sync.Mutex
	hashingActive   bool
	hashingDone     bool
	hashingProgress int
	hashingTotal    int
}

// NewServer initializes and returns a new Server instance. It sets up the router,
// parses templates from the embedded assets filesystem, and registers the server routes.
func NewServer(rootDir string) (*Server, error) {
	s := &Server{
		mux:       http.NewServeMux(),
		rootDir:   rootDir,
		clients:   make(map[chan string]bool),
	}

	// Parse templates from embedded FS
	tmpl, err := template.ParseFS(Assets, "assets/templates/*.html")
	if err != nil {
		return nil, err
	}
	s.templates = tmpl

	s.routes()
	return s, nil
}

// ServeHTTP implements the http.Handler interface, dispatching incoming requests
// to the registered server handlers.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// routes registers all webpage and API handlers for the Server.
func (s *Server) routes() {
	// Static assets
	subFS, err := fs.Sub(Assets, "assets/static")
	if err != nil {
		panic(err)
	}
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(subFS))))

	// Pages
	s.mux.HandleFunc("/", s.handleIndex)

	// APIs
	s.mux.HandleFunc("/api/start", s.handleStart)
	s.mux.HandleFunc("/api/progress", s.handleProgressSSE)
	s.mux.HandleFunc("/api/explore", s.handleExplore)
	s.mux.HandleFunc("/api/artifacts", s.handleArtifacts)
	s.mux.HandleFunc("/api/import", s.handleImport)
	s.mux.HandleFunc("/api/verify", s.handleVerify)
	s.mux.HandleFunc("/api/export/manifest", s.handleExportManifest)
	s.mux.HandleFunc("/api/export/report.json", s.handleExportReportJSON)
	s.mux.HandleFunc("/api/export/report.html", s.handleExportReportHTML)
	s.mux.HandleFunc("/dashboard", s.handleDashboard)
}

// handleIndex serves the root index page of the web application.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	err := s.templates.ExecuteTemplate(w, "base.html", nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

type StartRequest struct {
	Directory string `json:"directory"`
	CaseID    string `json:"case_id"`
	CaseName  string `json:"case_name"`
	Analyst   string `json:"analyst"`
}

// handleStart begins the asynchronous concurrent hashing of the target directory.
// It initializes progress tracking state and launches background goroutines to hash
// the files and broadcast updates.
func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req StartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	targetDir := normalizeLocalPath(req.Directory)
	if targetDir == "" {
		targetDir = normalizeLocalPath(s.rootDir) // fallback
	}

	// Update hashing state thread-safely
	s.stateMu.Lock()
	s.hashingActive = true
	s.hashingDone = false
	s.hashingProgress = 0
	s.hashingTotal = 0
	s.stateMu.Unlock()

	progressChan := make(chan hashing.ProgressUpdate, 100)

	go func() {
		hasher := hashing.NewHasher(targetDir)
		manifest, err := hasher.GenerateManifest(progressChan)
		if err != nil {
			fmt.Printf("Hashing error: %v\n", err)
			s.stateMu.Lock()
			s.hashingActive = false
			s.hashingDone = false
			s.stateMu.Unlock()
			return
		}
		manifest.CaseMetadata.CaseID = strings.TrimSpace(req.CaseID)
		manifest.CaseMetadata.CaseName = strings.TrimSpace(req.CaseName)
		manifest.CaseMetadata.Analyst = strings.TrimSpace(req.Analyst)
		
		timestamp := time.Now().Format("20060102_150405")
		filename := fmt.Sprintf("manifest_%s.json", timestamp)
		manifest.SaveToFile(filename)
		s.currentManifest = manifest
		s.currentRootDir = targetDir
		s.lastVerification = nil
		
		s.stateMu.Lock()
		s.hashingActive = false
		s.hashingDone = true
		s.hashingTotal = manifest.CaseMetadata.TotalArtifacts
		s.stateMu.Unlock()
		
		s.broadcastSSE(fmt.Sprintf(`{"processed": %d, "total": %d, "done": true}`, manifest.CaseMetadata.TotalArtifacts, manifest.CaseMetadata.TotalArtifacts))
	}()

	go func() {
		for progress := range progressChan {
			s.stateMu.Lock()
			s.hashingProgress = progress.Processed
			s.hashingTotal = progress.Total
			s.stateMu.Unlock()
			s.broadcastSSE(fmt.Sprintf(`{"processed": %d, "total": %d, "done": false}`, progress.Processed, progress.Total))
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

// broadcastSSE sends an SSE message to all connected clients. It utilizes non-blocking
// sends to prevent deadlocks from slow or disconnected clients.
func (s *Server) broadcastSSE(msg string) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()
	for clientChan := range s.clients {
		select {
		case clientChan <- msg:
		default:
			// Non-blocking write: drop message if client buffer is full to prevent deadlocks
		}
	}
}

// handleProgressSSE serves the Server-Sent Events (SSE) streaming endpoint. It streams
// real-time file processing counts and completion events to the web interface.
func (s *Server) handleProgressSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	// Check current state first
	s.stateMu.Lock()
	isDone := s.hashingDone
	isActive := s.hashingActive
	progress := s.hashingProgress
	total := s.hashingTotal
	s.stateMu.Unlock()

	if isDone {
		fmt.Fprintf(w, "data: {\"processed\": %d, \"total\": %d, \"done\": true}\n\n", total, total)
		flusher.Flush()
		return
	}

	// Create a buffered channel to avoid blocking the publisher
	clientChan := make(chan string, 100)
	s.clientsMu.Lock()
	s.clients[clientChan] = true
	s.clientsMu.Unlock()

	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, clientChan)
		s.clientsMu.Unlock()
		// Let garbage collector reclaim the channel to avoid panic on write
	}()

	// Send current progress immediately if active
	if isActive {
		fmt.Fprintf(w, "data: {\"processed\": %d, \"total\": %d, \"done\": false}\n\n", progress, total)
		flusher.Flush()
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case msg := <-clientChan:
			fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

type FileEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"is_dir"`
}

// handleExplore lists the contents of the requested directory for the folder navigation explorer UI.
// On Windows, if the path is empty, it returns the logical drive letters.
func (s *Server) handleExplore(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")
	if dir == "" || dir == "This PC" {
		if runtime.GOOS == "windows" {
			// List Windows Logical Drives
			var results []FileEntry
			for _, d := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
				path := string(d) + ":\\"
				if _, err := os.Stat(path); err == nil {
					results = append(results, FileEntry{
						Name:  path,
						Path:  path,
						IsDir: true,
					})
				}
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"current_dir": "This PC",
				"entries":     results,
			})
			return
		}

		// On macOS/Linux there are no drive letters; start at the
		// filesystem root and let the user navigate from there.
		dir = "/"
	}

	// Always make it an absolute, clean path
	dir = filepath.Clean(dir)

	entries, err := os.ReadDir(dir)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var results []FileEntry
	
	// Add parent directory option
	parentDir := filepath.Dir(dir)
	if parentDir != dir {
		results = append(results, FileEntry{
			Name:  "..",
			Path:  parentDir,
			IsDir: true,
		})
	} else {
		// We are at the root of a drive (e.g., C:\), go back to "This PC"
		results = append(results, FileEntry{
			Name:  "..",
			Path:  "This PC",
			IsDir: true,
		})
	}

	for _, e := range entries {
		// Only list directories for this feature
		if !e.IsDir() {
			continue
		}
		
		results = append(results, FileEntry{
			Name:  e.Name(),
			Path:  filepath.Join(dir, e.Name()),
			IsDir: true,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"current_dir": dir,
		"entries":     results,
	})
}

// handleDashboard serves the HTML dashboard page showing stats and the artifact explorer.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if s.currentManifest == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	err := s.templates.ExecuteTemplate(w, "base.html", map[string]interface{}{
		"Page": "dashboard",
		"Manifest": s.currentManifest,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleArtifacts provides a paginated and searchable JSON endpoint of all case artifacts
// stored in the loaded manifest.
func (s *Server) handleArtifacts(w http.ResponseWriter, r *http.Request) {
	if s.currentManifest == nil {
		http.Error(w, "No manifest loaded", http.StatusBadRequest)
		return
	}

	query := strings.ToLower(r.URL.Query().Get("q"))
	pageStr := r.URL.Query().Get("page")
	page, _ := strconv.Atoi(pageStr)
	if page < 1 {
		page = 1
	}
	limit := 50

	var filtered []models.Artifact
	for _, art := range s.currentManifest.Artifacts {
		if query == "" || 
		   strings.Contains(strings.ToLower(art.Path), query) || 
		   strings.Contains(strings.ToLower(art.SHA256), query) ||
		   strings.Contains(strings.ToLower(art.MD5), query) {
			filtered = append(filtered, art)
		}
	}

	total := len(filtered)
	start := (page - 1) * limit
	end := start + limit

	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	paginated := filtered[start:end]

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"artifacts": paginated,
		"total":     total,
		"page":      page,
		"limit":     limit,
	})
}

// handleImport accepts a POST file upload containing a manifest JSON file, validates its
// structure, saves it to a unique file locally, and loads it as the active manifest.
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit upload size to 10MB
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)

	file, _, err := r.FormFile("manifest")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to read uploaded file: " + err.Error()})
		return
	}
	defer file.Close()

	var manifest models.MasterManifest
	if err := json.NewDecoder(file).Decode(&manifest); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON format: " + err.Error()})
		return
	}

	// Schema validation: check that case_metadata exists and artifacts is not nil
	if manifest.CaseMetadata.CreationTimestamp == nil && len(manifest.Artifacts) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid manifest structure: missing case_metadata or artifacts"})
		return
	}

	s.currentManifest = &manifest
	s.currentRootDir = ""
	s.lastVerification = nil

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

type VerificationResult struct {
	Verified      int                  `json:"verified"`
	Missing       int                  `json:"missing"`
	Modified      int                  `json:"modified"`
	Extra         int                  `json:"extra"`
	TotalExpected int                  `json:"total_expected"`
	TotalCurrent  int                  `json:"total_current"`
	Directory     string               `json:"directory"`
	Details       []VerificationDetail `json:"details"`
	VerifiedAt    *time.Time           `json:"verified_at,omitempty"`
}

type VerificationDetail struct {
	Status         string `json:"status"`
	Path           string `json:"path"`
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	ActualSHA256   string `json:"actual_sha256,omitempty"`
}

type VerifyRequest struct {
	Directory string `json:"directory"`
}

// handleVerify re-hashes the original case directory and compares the result
// against the loaded manifest.
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.currentManifest == nil {
		http.Error(w, "No manifest loaded", http.StatusBadRequest)
		return
	}

	var req VerifyRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	targetDir := normalizeLocalPath(req.Directory)
	if targetDir == "" {
		targetDir = normalizeLocalPath(s.currentRootDir)
	}

	if targetDir == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "This manifest was imported. Enter the local evidence folder path to verify it against this manifest.",
			"code":  "directory_required",
		})
		return
	}

	if info, err := os.Stat(targetDir); err != nil || !info.IsDir() {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Verification directory does not exist or is not a folder: " + targetDir,
		})
		return
	}

	hasher := hashing.NewHasher(targetDir)
	freshManifest, err := hasher.GenerateManifest(nil)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	unmatchedExpected := make([]models.Artifact, 0)
	unmatchedCurrent := make(map[string]models.Artifact)
	for _, art := range freshManifest.Artifacts {
		unmatchedCurrent[art.Path] = art
	}

	result := VerificationResult{
		TotalExpected: len(s.currentManifest.Artifacts),
		TotalCurrent:  len(freshManifest.Artifacts),
		Directory:     targetDir,
	}

	for _, expected := range s.currentManifest.Artifacts {
		current, ok := unmatchedCurrent[expected.Path]
		if ok {
			if current.SHA256 != expected.SHA256 {
				result.Modified++
				result.Details = append(result.Details, VerificationDetail{
					Status:         "modified",
					Path:           expected.Path,
					ExpectedSHA256: expected.SHA256,
					ActualSHA256:   current.SHA256,
				})
			} else {
				result.Verified++
			}
			delete(unmatchedCurrent, expected.Path)
		} else {
			unmatchedExpected = append(unmatchedExpected, expected)
		}
	}

	currentByHash := make(map[string][]models.Artifact)
	for _, current := range unmatchedCurrent {
		currentByHash[current.SHA256] = append(currentByHash[current.SHA256], current)
	}

	for _, expected := range unmatchedExpected {
		candidates, ok := currentByHash[expected.SHA256]
		if ok && len(candidates) > 0 {
			current := candidates[0]
			currentByHash[expected.SHA256] = candidates[1:]
			delete(unmatchedCurrent, current.Path)

			result.Modified++
			result.Details = append(result.Details, VerificationDetail{
				Status:         "modified",
				Path:           fmt.Sprintf("%s -> %s", expected.Path, current.Path),
				ExpectedSHA256: expected.SHA256,
				ActualSHA256:   current.SHA256,
			})
		} else {
			result.Missing++
			result.Details = append(result.Details, VerificationDetail{
				Status:         "missing",
				Path:           expected.Path,
				ExpectedSHA256: expected.SHA256,
			})
		}
	}

	for _, current := range unmatchedCurrent {
		result.Extra++
		result.Details = append(result.Details, VerificationDetail{
			Status:       "extra",
			Path:         current.Path,
			ActualSHA256: current.SHA256,
		})
	}

	now := time.Now().UTC()
	result.VerifiedAt = &now
	s.lastVerification = &result

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func normalizeLocalPath(path string) string {
	path = strings.TrimSpace(path)
	path = strings.Trim(path, "\"'")
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}

	// Users often paste JSON-escaped Windows paths such as
	// "D:\\Evidence\\Case001" into the verification field.
	if runtime.GOOS == "windows" {
		path = strings.ReplaceAll(path, `\\`, `\`)
	}

	return filepath.Clean(path)
}

func (s *Server) handleExportManifest(w http.ResponseWriter, r *http.Request) {
	if s.currentManifest == nil {
		http.Error(w, "No manifest loaded", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="master_manifest.json"`)
	json.NewEncoder(w).Encode(s.currentManifest)
}

type IntegrityReport struct {
	GeneratedAt   time.Time            `json:"generated_at"`
	Manifest      *models.MasterManifest `json:"manifest"`
	Verification  *VerificationResult  `json:"verification,omitempty"`
	LoadedRootDir string               `json:"loaded_root_dir,omitempty"`
}

func (s *Server) buildReport() (*IntegrityReport, error) {
	if s.currentManifest == nil {
		return nil, fmt.Errorf("no manifest loaded")
	}
	return &IntegrityReport{
		GeneratedAt:   time.Now().UTC(),
		Manifest:      s.currentManifest,
		Verification:  s.lastVerification,
		LoadedRootDir: s.currentRootDir,
	}, nil
}

func (s *Server) handleExportReportJSON(w http.ResponseWriter, r *http.Request) {
	report, err := s.buildReport()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="integrity_report.json"`)
	json.NewEncoder(w).Encode(report)
}

func (s *Server) handleExportReportHTML(w http.ResponseWriter, r *http.Request) {
	report, err := s.buildReport()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	html, err := renderIntegrityReportHTML(report)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="integrity_report.html"`)
	w.Write(html)
}

func renderIntegrityReportHTML(report *IntegrityReport) ([]byte, error) {
	const reportTemplate = `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<title>Integrity Report</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 2rem; color: #111827; }
		h1, h2 { color: #0f172a; }
		.meta, table { width: 100%; border-collapse: collapse; margin: 1rem 0 2rem; }
		td, th { border: 1px solid #d1d5db; padding: 0.5rem; text-align: left; vertical-align: top; }
		th { background: #f3f4f6; }
		code { font-family: Consolas, monospace; word-break: break-all; }
		.ok { color: #047857; font-weight: 700; }
		.warn { color: #b45309; font-weight: 700; }
		.bad { color: #b91c1c; font-weight: 700; }
	</style>
</head>
<body>
	<h1>Evidence Integrity Report</h1>
	<table class="meta">
		<tr><th>Generated at</th><td>{{.GeneratedAt}}</td></tr>
		<tr><th>Manifest version</th><td>{{.Manifest.CaseMetadata.ManifestVersion}}</td></tr>
		<tr><th>Source path</th><td><code>{{.Manifest.CaseMetadata.SourcePath}}</code></td></tr>
		<tr><th>Total artifacts</th><td>{{.Manifest.CaseMetadata.TotalArtifacts}}</td></tr>
		<tr><th>Total bytes</th><td>{{.Manifest.CaseMetadata.TotalBytes}}</td></tr>
		<tr><th>Merkle root</th><td><code>{{.Manifest.CaseMetadata.CaseRootHash}}</code></td></tr>
	</table>

	{{if .Verification}}
	<h2>Verification Summary</h2>
	<table>
		<tr><th>Verified at</th><td>{{.Verification.VerifiedAt}}</td></tr>
		<tr><th>Compared directory</th><td><code>{{.Verification.Directory}}</code></td></tr>
		<tr><th>Verified</th><td class="ok">{{.Verification.Verified}}</td></tr>
		<tr><th>Missing</th><td class="bad">{{.Verification.Missing}}</td></tr>
		<tr><th>Modified</th><td class="warn">{{.Verification.Modified}}</td></tr>
		<tr><th>Extra</th><td>{{.Verification.Extra}}</td></tr>
	</table>

	<h2>Verification Details</h2>
	<table>
		<thead><tr><th>Status</th><th>Path</th><th>Expected SHA256</th><th>Actual SHA256</th></tr></thead>
		<tbody>
		{{if .Verification.Details}}
			{{range .Verification.Details}}
			<tr><td>{{.Status}}</td><td><code>{{.Path}}</code></td><td><code>{{.ExpectedSHA256}}</code></td><td><code>{{.ActualSHA256}}</code></td></tr>
			{{end}}
		{{else}}
			<tr><td colspan="4" class="ok">All manifest entries match the selected folder.</td></tr>
		{{end}}
		</tbody>
	</table>
	{{else}}
	<p>No verification has been run during this session.</p>
	{{end}}

	<h2>Manifest Artifacts</h2>
	<table>
		<thead><tr><th>Path</th><th>Size</th><th>SHA256</th></tr></thead>
		<tbody>
			{{range .Manifest.Artifacts}}
			<tr><td><code>{{.Path}}</code></td><td>{{.SizeBytes}}</td><td><code>{{.SHA256}}</code></td></tr>
			{{end}}
		</tbody>
	</table>
</body>
</html>`

	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, report); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
