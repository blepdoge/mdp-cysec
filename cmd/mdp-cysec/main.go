package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/user/mdp-cysec/internal/web"
)

func main() {
	port := flag.Int("port", 8080, "Port to run the web server on")
	rootDir := flag.String("dir", "C:/Users/Louis-Marie/Documents", "Target evidence directory")
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
