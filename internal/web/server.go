package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"mdp-cysec/internal/hashing"
	"mdp-cysec/internal/models"
)

type Server struct {
	mux           *http.ServeMux
	templates     *template.Template
	rootDir       string
	
	progressChan    chan int
	clients         map[chan string]bool
	clientsMu       sync.Mutex
	currentManifest *models.MasterManifest
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

	s.progressChan = make(chan int)

	go func() {
		hasher := hashing.NewHasher(targetDir)
		manifest, err := hasher.GenerateManifest(s.progressChan)
		if err != nil {
			fmt.Printf("Hashing error: %v\n", err)
			return
		}
		
		manifest.SaveToFile("master_manifest.json")
		s.currentManifest = manifest
		
		s.broadcastSSE(fmt.Sprintf(`{"processed": %d, "done": true}`, manifest.CaseMetadata.TotalArtifacts))
	}()

	go func() {
		for progress := range s.progressChan {
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
		clientChan <- msg
	}
}

func (s *Server) handleProgressSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	clientChan := make(chan string)
	s.clientsMu.Lock()
	s.clients[clientChan] = true
	s.clientsMu.Unlock()

	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, clientChan)
		s.clientsMu.Unlock()
		close(clientChan)
	}()

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
