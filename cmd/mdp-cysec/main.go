package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"mdp-cysec/internal/hashing"
	"mdp-cysec/internal/web"
)

func main() {
	port := flag.Int("port", 8080, "Port to run the web server on")
	rootDir := flag.String("dir", "", "Target evidence directory")
	tsaURL := flag.String("tsa", "https://freetsa.org/tsr", "RFC 3161 timestamping authority URL (empty to disable timestamping)")
	cliMode := flag.Bool("cli", false, "Run in CLI/batch hashing mode and output summary")
	snapshotDir := flag.String("snapshots", "", "Directory to store snapshots (optional)")
	flag.Parse()

	if *cliMode {
		if *rootDir == "" {
			log.Fatal("Error: -dir must be specified in CLI mode")
		}
		start := time.Now()
		hasher := hashing.NewHasher(*rootDir, *snapshotDir)
		manifest, err := hasher.GenerateManifest(nil)
		if err != nil {
			log.Fatalf("Hashing failed: %v", err)
		}
		elapsed := time.Since(start)
		mb := float64(manifest.CaseMetadata.TotalBytes) / (1024 * 1024)
		throughput := mb / elapsed.Seconds()
		fmt.Printf("Processed %d artifacts (%.2f MB) in %v (%.2f MB/s)\n",
			manifest.CaseMetadata.TotalArtifacts, mb, elapsed, throughput)
		return
	}

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

