package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"mdp-cysec/internal/web"
)

func main() {
	defaultDir, err := os.UserHomeDir()
	if err != nil {
		defaultDir = "."
	}

	port := flag.Int("port", 8080, "Port to run the web server on")
	rootDir := flag.String("dir", defaultDir, "Target evidence directory")
	flag.Parse()

	server, err := web.NewServer(*rootDir)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	addr := fmt.Sprintf(":%d", *port)
	fmt.Printf("Starting mdp-cysec web interface on http://localhost%s\n", addr)
	fmt.Printf("Evidence Root: %s\n", *rootDir)

	if err := http.ListenAndServe(addr, server); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
