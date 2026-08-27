# mdp-cysec: evidence integrity manager

A local Go application with an embedded web interface to manage, hash, and verify the integrity of forensic evidence directories.

## Features

### 1. High-performance hashing engine
- **Concurrent hashing**: uses a worker pool (`runtime.NumCPU() * 2`) to scan and hash forensic artifacts in parallel.
- **Single-pass multi-hashing**: computes `SHA256`, `SHA1`, and `MD5` simultaneously in a single read pass over each file.
- **Master manifest**: records artifact paths, sizes, and hashes in a structured JSON manifest with case metadata.
- **Pipelined directory traversal**: streams files into worker queues during traversal with adaptive buffer pooling (64 KB for small files, 4 MB for large files).

### 2. Embedded web server and live progress
- **Zero external web dependencies**: built entirely with Go's standard `net/http` and `html/template` packages.
- **Embedded static assets**: uses Go's `embed` package to compile all HTML templates and CSS directly into the binary.
- **Server-sent events (SSE)**: streams live progress updates from the hashing worker pool to the browser.

### 3. Case import and exploration
- **Manifest import**: allows loading pre-calculated cases by uploading an existing `master_manifest.json` file.
- **Schema validation**: validates uploaded manifests and reports format errors.

### 4. Interactive web dashboard
- **Tabbed layout**: dedicated tabs for artifact exploration, deep diff analysis, and report exhibits.
- **Overview metrics**: displays status cards for verified, missing, modified, and extra files.
- **Deep diff analysis**: visual side-by-side diffing of text files and decoded image formats (PNG, JPEG, GIF, BMP, TIFF, WebP, RAW).

### 5. Merkle root and RFC 3161 timestamping
- **Binary Merkle tree**: calculates a deterministic Merkle root over the artifact SHA256 hashes.
- **Canonical ordering**: sorts artifacts by name and relative path before sealing so the manifest and Merkle root are reproducible.
- **RFC 3161 attestation**: submits the Merkle root to a timestamping authority (`https://freetsa.org/tsr` by default, configurable with `-tsa`) and saves the token as a `.tsr` file.

### 6. Integrity verification workflow
- **Re-verification**: re-hashes an evidence directory and compares it against the baseline manifest.
- **Status classification**: classifies files into `verified`, `modified`, `missing`, and `extra`.
- **Report exports**: exports manifests, JSON reports, and standalone HTML integrity reports with quoted exhibits.

## Why this exists

`mdp-cysec` helps preserve forensic evidence integrity. At acquisition time, it creates a cryptographic manifest of a folder. Later, it verifies whether that folder still matches the manifest.

The verification result answers four questions:

- `verified`: file exists and hashes match.
- `modified`: file exists but content changed.
- `missing`: file was in the manifest but is no longer present.
- `extra`: file exists now but was not in the manifest.

## How to run locally

1. Run the application via the CLI:
   ```bash
   go run cmd/mdp-cysec/main.go
   ```
2. Open `http://localhost:8080` in your browser.
3. Click **Start new case** to select a directory to hash, or **Import existing case** to upload a manifest file.

### CLI batch and benchmarking mode

You can also run `mdp-cysec` in headless CLI mode to hash directories directly and measure throughput:
```bash
# Direct CLI batch hashing
go run cmd/mdp-cysec/main.go -cli -dir /path/to/evidence

# With optional baseline snapshotting enabled
go run cmd/mdp-cysec/main.go -cli -dir /path/to/evidence -snapshots /path/to/snapshots
```

## Performance benchmarks

`mdp-cysec`'s hashing engine was benchmarked head-to-head against state-of-the-art multi-hash tools (**RHash v1.4.6** and **HashDeep v4.4**) using [`hyperfine`](https://github.com/sharkdp/hyperfine). Each tool was configured to compute **MD5, SHA-1, and SHA-256 simultaneously** across all files in a single pass.

*Benchmarked on Intel Core Ultra 7 155H (22 logical cores, NVMe SSD, Windows 11).*

### 1. Real-world evidence dataset (2.08 GB, 1,994 files)

A mixed real-world dataset comprising nested directories, audio samples, libraries, and config files.

| Tool | Configuration | Mean execution time ($\pm\ \sigma$) | Effective throughput | Relative speed |
| :--- | :--- | :--- | :--- | :--- |
| **`mdp-cysec`** | 44 worker goroutines | **$1.293\text{ s} \pm 0.071\text{ s}$** | **$\approx 1,608\text{ MB/s}$** | **$1.00\times$ (fastest)** |
| **`HashDeep` (v4.4)** | `-j 22` (22 threads) | $3.071\text{ s} \pm 0.129\text{ s}$ | $\approx 677\text{ MB/s}$ | $2.38\times$ slower |
| **`RHash` (v1.4.6)** | Single-threaded | $9.897\text{ s} \pm 0.407\text{ s}$ | $\approx 210\text{ MB/s}$ | $7.66\times$ slower |

### 2. Synthetic workload: small files (1,000 files in subdirectories)

Tests directory traversal pipelining, metadata syscalls, and adaptive memory pool efficiency.

| Tool | Configuration | Mean execution time ($\pm\ \sigma$) | Relative speed |
| :--- | :--- | :--- | :--- |
| **`mdp-cysec`** | 44 worker goroutines | **$71.9\text{ ms} \pm 10.1\text{ ms}$** | **$1.00\times$ (fastest)** |
| **`RHash` (v1.4.6)** | Single-threaded | $213.3\text{ ms} \pm 14.6\text{ ms}$ | $2.97\times$ slower |
| **`HashDeep` (v4.4)** | `-j 22` (22 threads) | $310.5\text{ ms} \pm 14.8\text{ ms}$ | $4.32\times$ slower |

### 3. Synthetic workload: large files ($3 \times 50\text{ MB} = 150\text{ MB}$)

Tests streaming buffer saturation, zero-allocation digest buffers, and hardware crypto extensions (SHA-NI / AVX2).

| Tool | Configuration | Mean execution time ($\pm\ \sigma$) | Effective throughput | Relative speed |
| :--- | :--- | :--- | :--- | :--- |
| **`mdp-cysec`** | 44 worker goroutines | **$229.8\text{ ms} \pm 6.3\text{ ms}$** | **$\approx 653\text{ MB/s}$** | **$1.00\times$ (fastest)** |
| **`RHash` (v1.4.6)** | Single-threaded | $711.3\text{ ms} \pm 16.9\text{ ms}$ | $\approx 211\text{ MB/s}$ | $3.10\times$ slower |
| **`HashDeep` (v4.4)** | `-j 22` (22 threads) | $1588.0\text{ ms} \pm 62.0\text{ ms}$ | $\approx 94\text{ MB/s}$ | $6.91\times$ slower |

### Reproducing the benchmarks

You can reproduce these benchmarks using `hyperfine`:

```bash
# Build the binary
go build -o mdp-cysec.exe ./cmd/mdp-cysec

# Run comparative benchmark across tools
hyperfine --warmup 2 --runs 5 \
  "./mdp-cysec.exe -cli -dir /path/to/target" \
  "hashdeep64 -c md5,sha1,sha256 -r -j 22 /path/to/target" \
  "rhash -r -M -H --sha256 /path/to/target"
```

## Demo data

Use `example_manifest.json` with these folders to test the verification workflow:

- `testdata/sample_case`: clean match.
- `testdata/sample_case_modified`: one modified file.
- `testdata/sample_case_missing`: one missing file.
- `testdata/sample_case_extra`: one unexpected extra file.

