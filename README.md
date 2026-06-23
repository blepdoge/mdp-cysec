# mdp-cysec: Evidence Integrity Manager

This project aims to build a local Go application with a web frontend to manage and verify the integrity of forensic evidence directories.

## Current Status & Implemented Features

The project currently has two major milestones completed on the `main` branch:

### 1. High-Performance Hashing Engine (Issue #1)
- **Concurrent Hashing**: Utilizes a highly optimized worker pool (bounded by `runtime.NumCPU() * 2`) to scan and hash forensic artifacts simultaneously.
- **Multiple Hashes**: Computes `SHA256`, `SHA1`, and `MD5` hashes simultaneously in a single file pass using `io.MultiWriter`.
- **Master Manifest**: Formats the resulting metadata into a standard JSON `MasterManifest` structure, containing case metadata and individual artifact hashes.
- **Memory Efficiency**: Utilizes `filepath.WalkDir` over standard `Walk` for drastically faster directory enumeration without thrashing the disk or hitting file handle limits.

### 2. Local Web Server & Dynamic UI (Issue #2)
- **Zero-Dependency Web Server**: Built strictly using Go's native `net/http` and `html/template` packages. 
- **Binary Embedded Assets**: Utilizes Go's `embed` package to compile all CSS and HTML templates directly into the final executable, meaning no loose web files are required for distribution.
- **Server-Sent Events (SSE)**: The backend provides an `/api/progress` streaming endpoint. This channels live processing numbers from the hashing worker pool directly to the web UI without the need for heavy WebSocket libraries or repeated polling.
- **Modern UI Design**: The frontend utilizes a completely dependency-free Vanilla CSS layout. It features a modern dark mode, glassmorphism paneling (`backdrop-filter`), CSS animations, and gradient styling to create a premium feel. 

## How to Run Locally

1. Run the application via the CLI:
   ```bash
   go run cmd/mdp-cysec/main.go -dir "C:/path/to/evidence/folder"
   ```
2. Navigate to `http://localhost:8080` in your browser.
3. Click **Start New Case** to observe the hashing engine processing files in real-time through the SSE UI stream.
