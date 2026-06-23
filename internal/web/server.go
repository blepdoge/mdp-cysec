package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"sync"

	"github.com/user/mdp-cysec/internal/hashing"
)

type Server struct {
	mux           *http.ServeMux
	templates     *template.Template
	rootDir       string
	
	progressChan  chan int
	clients       map[chan string]bool
	clientsMu     sync.Mutex
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

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.progressChan = make(chan int)

	go func() {
		hasher := hashing.NewHasher(s.rootDir)
		manifest, err := hasher.GenerateManifest(s.progressChan)
		if err != nil {
			fmt.Printf("Hashing error: %v\n", err)
			return
		}
		
		manifest.SaveToFile("master_manifest.json")
		
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
