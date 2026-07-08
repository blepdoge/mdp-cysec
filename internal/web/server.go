package web

import (
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

	// Thread-safe state tracking for hashing progress
	stateMu         sync.Mutex
	hashingActive   bool
	hashingDone     bool
	hashingProgress int
	hashingTotal    int
}

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

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

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
	s.mux.HandleFunc("/dashboard", s.handleDashboard)
}

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
}

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

	targetDir := req.Directory
	if targetDir == "" {
		targetDir = s.rootDir // fallback
	}

	// Update hashing state thread-safely
	s.stateMu.Lock()
	s.hashingActive = true
	s.hashingDone = false
	s.hashingProgress = 0
	s.hashingTotal = 0
	s.stateMu.Unlock()

	progressChan := make(chan int, 100)

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
		
		timestamp := time.Now().Format("20060102_150405")
		filename := fmt.Sprintf("manifest_%s.json", timestamp)
		manifest.SaveToFile(filename)
		s.currentManifest = manifest
		
		s.stateMu.Lock()
		s.hashingActive = false
		s.hashingDone = true
		s.hashingTotal = manifest.CaseMetadata.TotalArtifacts
		s.stateMu.Unlock()
		
		s.broadcastSSE(fmt.Sprintf(`{"processed": %d, "done": true}`, manifest.CaseMetadata.TotalArtifacts))
	}()

	go func() {
		for progress := range progressChan {
			s.stateMu.Lock()
			s.hashingProgress = progress
			s.stateMu.Unlock()
			s.broadcastSSE(fmt.Sprintf(`{"processed": %d, "done": false}`, progress))
		}
	}()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

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
		fmt.Fprintf(w, "data: {\"processed\": %d, \"done\": true}\n\n", total)
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
		fmt.Fprintf(w, "data: {\"processed\": %d, \"done\": false}\n\n", progress)
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

	// Save the manifest to master_manifest.json in the current working directory
	if err := manifest.SaveToFile("master_manifest.json"); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "Failed to save manifest locally: " + err.Error()})
		return
	}

	s.currentManifest = &manifest

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}
