package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"mdp-cysec/internal/web"
)

func main() {
	port := flag.Int("port", 8080, "Port to run the web server on")
	rootDir := flag.String("dir", "", "Target evidence directory")
	tsaURL := flag.String("tsa", "https://freetsa.org/tsr", "RFC 3161 timestamping authority URL (empty to disable timestamping)")
	flag.Parse()

	server, err := web.NewServer(*rootDir, *tsaURL)
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
