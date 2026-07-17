# mdp-cysec: Evidence Integrity Manager

This project aims to build a local Go application with a web frontend to manage and verify the integrity of forensic evidence directories.

## Current status & implemented features

The project currently has two major milestones completed on the `main` branch:

### 1. High-performance hashing engine (Issue #1)
- **Concurrent hashing**: Utilizes a highly optimized worker pool (bounded by `runtime.NumCPU() * 2`) to scan and hash forensic artifacts simultaneously.
- **Multiple hashes**: Computes `SHA256`, `SHA1`, and `MD5` hashes simultaneously in a single file pass using `io.MultiWriter`.
- **Master manifest**: Formats the resulting metadata into a standard JSON `MasterManifest` structure, containing case metadata and individual artifact hashes.
- **Memory efficiency**: Utilizes `filepath.WalkDir` over standard `Walk` for drastically faster directory enumeration without thrashing the disk or hitting file handle limits.

### 2. Local web server & SSE(Issue #2)
- **Zero-dependency web server**: Built strictly using Go's native `net/http` and `html/template` packages. 
- **Binary embedded assets**: Utilizes Go's `embed` package to compile all CSS and HTML templates directly into the final executable, meaning no loose web files are required for distribution.
- **Server-sent events (SSE)**: The backend provides an `/api/progress` streaming endpoint. This channels live processing numbers from the hashing worker pool directly to the web UI without the need for heavy WebSocket libraries or repeated polling.

### 3. Case Import Feature (Issue #7)
- **Manifest Selection**: Enables importing pre-calculated case results by uploading an existing `master_manifest.json` file.
- **Robust Schema Validation**: Checks uploaded JSON schemas for metadata and artifact structures, rendering inline error messages for wrong/invalid formats.

### 4. Interactive HTML Dashboard (Issue #6)
- **Tabbed Layout**: Implements a dedicated tab system for the **Artifact Explorer** and **Report Exhibits** to optimize screen space and prevent layout squishing.
- **Overview Metrics**: Displays status cards for **Verified**, **Missing**, and **Modified** files.
- **Back-and-Forth Navigation**: Features seamless transitions between tabs, prompting users to view exhibits after quoting, or return to the explorer when the report is empty.
- **Merkle & RFC Placeholders**: Includes visual zones prepared for future Merkle root hashing and RFC 3161 timestamping integrations.

### 5. Merkle Root & RFC 3161 Timestamping (Issue #3)
- **Binary Merkle tree**: Native Go implementation over the artifact SHA256 hashes. Odd node counts duplicate the last node against itself (Bitcoin-style). The root is stored as `case_root_hash` in the manifest.
- **Canonical artifact ordering**: Artifacts are sorted by file name (path as tie-breaker) before the manifest is written, so the same evidence set always produces the same Merkle root.
- **RFC 3161 attestation**: The Merkle root is sent to a timestamping authority (default: `https://freetsa.org/tsr`, configurable via the `-tsa` flag) and the returned token is saved as `manifest_<timestamp>.tsr` next to the manifest. Implemented with `encoding/asn1` only — no external dependencies. Timestamping is best-effort: if the TSA is unreachable, the manifest is still saved (local-first).

### 6. Integrity Verification Workflow (Issue #5)
- **Real verification endpoint**: Re-hashes a selected evidence directory and compares it against the loaded manifest.
- **Clear result classes**: Detects `verified`, `missing`, `modified`, and `extra` files.
- **Richer manifests**: Manifests include case metadata, evidence directory, total bytes, file sizes, and hash sets.
- **Report exports**: The dashboard can export the active manifest, a JSON integrity report, and a standalone HTML integrity report.

## Why this exists

`mdp-cysec` helps preserve forensic evidence integrity. At acquisition time, it creates a cryptographic manifest of a folder. Later, it verifies whether that folder still matches the manifest.

The verification result answers four questions:

- `verified`: file still exists and its hashes match.
- `modified`: file exists but content changed.
- `missing`: file was in the manifest but is no longer present.
- `extra`: file exists now but was not in the manifest.

This provides a practical chain-of-custody aid: the manifest captures the original state, and verification proves whether the evidence set stayed stable.

## How to run locally

1. Run the application via the CLI:
   ```bash
   go run cmd/mdp-cysec/main.go
   ```
2. Navigate to `http://localhost:8080` in your browser.
3. Click **Start New Case** to select a directory to hash, or **Import existing case** to upload a manifest file.

## Demo data

Use `example_manifest.json` with these folders to test the verification workflow:

- `testdata/sample_case`: clean match.
- `testdata/sample_case_modified`: one modified file.
- `testdata/sample_case_missing`: one missing file.
- `testdata/sample_case_extra`: one unexpected extra file.
