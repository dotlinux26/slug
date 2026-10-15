# Slug: Secure, Ephemeral, Git-like Workspace Sharing & Synchronization

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![C++ Standard](https://img.shields.io/badge/Language-C%2B%2B20-blue.svg)](https://en.wikipedia.org/wiki/C%2B%2B20)
[![Post-Quantum Cryptography](https://img.shields.io/badge/PQC-ML--KEM--768%20%7C%20ML--DSA--65-success.svg)](https://csrc.nist.gov/Projects/post-quantum-cryptography)
[![Zero-Dependency Static Binary](https://img.shields.io/badge/Linux_Static-100%25_Portable-brightgreen.svg)](BUILD.md)

> **Slug** is a developer-first tool for securely sharing and synchronizing project workspaces across machines, featuring ephemeral access controls, sensitive-file AI shield, and native post-quantum cryptography.

---

## Overview & Philosophy

Modern developers, red teams, and security engineers frequently need to transfer codebases, artifacts, reports, and environment secrets between laptops, lab virtual machines, and cloud instances. Traditional tools force hard compromises:

- **Git** tracks immutable version histories and commits, but sharing an in-progress workspace requires git pushes, repo access, or leaks sensitive keys into commits.
- **rsync / scp / SSH** require system accounts, SSH key exchanges, and full shell privileges without fine-grained file screening or self-expiring sessions.
- **Cloud Drives** introduce third-party vendor access, compliance exposure, and unencrypted local sync caches.

**Slug bridges this gap**: It provides a **portable, high-performance P2P transfer plane** inspired by Git's content-addressable model (manifests, BLAKE3 chunk hashes, delta sync), hardened with **Post-Quantum Cryptography (NIST FIPS 203 / 204)**, **ephemeral RBAC credentials**, and an **in-memory AI Secret Guard**.

```
+-----------------------------------------------------------------------------------------+
|                                    SLUG ARCHITECTURE                                    |
+-----------------------------------------------------------------------------------------+
|  CONTROL PLANE (TCP/TLS/PQC)                  DATA PLANE (UDP Chunking & Anti-Replay)   |
|  - Kyber/ML-KEM-768 + Dilithium/ML-DSA-65     - 64 KiB Chunks with BLAKE3 Verification  |
|  - 8-Digit Single-Use TOTP (One-Time-Bind)    - 24-byte Header bound in AAD             |
|  - Ephemeral RBAC Accounts (r, w, rw)         - 64-bit Anti-Replay Sliding Window       |
+-----------------------------------------------------------------------------------------+
|  POLICY & INSPECTION ENGINE                                                             |
|  - Directory-Scoped Hierarchical .gitignore   - .slug/rules.conf (# <rule ...>)         |
|  - Stateful AI Secret Guard with BLAKE3 Caching (.slug/index.db)                        |
|  - Strict Path Confinement (Zero Directory Traversal)                                   |
+-----------------------------------------------------------------------------------------+
|  PQC ENVSHIELD (RAM-Only Secret Injection)                                              |
|  - Encrypted .env -> .env.pqc                  - Fork/Execve with In-Memory Env Vars    |
+-----------------------------------------------------------------------------------------+
```

---

## Key Capabilities

### 1. Three Cryptographic Security Suites
Slug supports protocol-negotiated security suites:
- **Suite 1 (`classical`)**: SHA-256 + Ed25519 + X25519 + XChaCha20-Poly1305.
- **Suite 2 (`modern`)**: BLAKE3 + Ed25519 + X25519 + XChaCha20-Poly1305.
- **Suite 3 (`pure-pqc`, Default)**: BLAKE3 + ML-DSA-65 (FIPS 204) + ML-KEM-768 (FIPS 203) + XChaCha20-Poly1305.

### 2. Ephemeral Access & One-Time TOTP Burn
- Each hosted workspace runs on its own isolated TCP/UDP port.
- Generates an **8-digit TOTP token** that is **atomically burned** on first connection, preventing replay attacks.
- Ephemeral accounts (`slug user add`) support customizable TTL durations (`--ttl 1h`, `24h`, `7d`) and roles (`r` read-only, `w` write-only, `rw` read-write).

### 3. Stateful AI Secret Guard (`.slug/index.db`)
- Scans files using heuristic pattern analyzers and Shannon entropy detectors for private keys, database connection strings, JWT tokens, and cloud API keys (`sk_live_`, `sk-`, AWS, GitHub).
- Caches clean content hashes in `.slug/index.db`: **subsequent syncs achieve 0ms overhead**.
- Flagged files are automatically excluded from manifests and transfers.
- Interactive remediation via `slug audit list`, `slug audit allow`, and `slug audit recheck`.

### 4. Git-like Delta Sync & Selective Pull
- Files are divided into 64 KiB content chunks with BLAKE3 integrity verification.
- **Delta Planner**: Only transfers modified chunks; unmodified files are skipped (zero bandwidth wasted).
- Supports selective filtering:
  - `--dry-run`: Preview transfer delta without writing to disk.
  - `--only <glob>`: Selective path transfer (e.g., `--only "src/*"`).
  - `--ext <exts>`: Extension filter (e.g., `--ext ".cpp,.hpp,.md"`).
  - `--max-size <bytes>`: Skip oversized files.
  - `--prune`: Automatically delete local files that were removed upstream.

### 5. PQC EnvShield: RAM-only Secret Injection
Protects sensitive `.env` files from leaking into Git repositories or being inspected by local AI coding agents:
- `slug env init`: Encrypts `.env` into `.env.pqc` using Suite 3 PurePQC envelope encryption and removes the plaintext `.env`.
- `slug env run -- <command...>`: Decrypts `.env.pqc` exclusively in RAM and injects variables into the target child process environment without writing any plaintext file to disk.

### 6. 100% Static Portable Release Binary
- Compiled as a single static executable (`bin/slug-static`, ~8.4 MB) with zero glibc or shared library dependencies.
- Runs out-of-the-box on **any Linux distribution** (Debian, Ubuntu, Alpine, RHEL, CentOS, Arch, NixOS) and inside scratch Docker containers.
- Full native support for Windows (`slug.exe`) and macOS.

---

## Installation & Packaging

Slug is distributed as a zero-dependency portable binary for both Linux and Windows.

### Linux (Any Distribution)

**One-line automated installation:**
```bash
curl -fsSL https://raw.githubusercontent.com/slugproject/slug/main/scripts/install.sh | bash
# or run locally:
./scripts/install.sh
```

**Debian / Ubuntu Package (.deb):**
```bash
./scripts/package_deb.sh
sudo dpkg -i dist/slug_1.0.0-rc1_amd64.deb
```

**Universal Static Tarball:**
```bash
tar -xzf dist/slug-1.0.0-rc1-linux-x86_64.tar.gz
sudo mv slug-1.0.0-rc1-linux-x86_64/slug /usr/local/bin/
```

### Windows (PowerShell)

**One-line automated installation:**
```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```
Or build natively with Visual Studio 2022: `scripts\build_windows.bat`.

### Comprehensive Tutorials
- [English Tutorial & Field Guide](TUTORIAL.md)
- [Hướng Dẫn Sử Dụng & Triển Khai Tiếng Việt](slug-docs/TUTORIAL_VI.md)

---

## Terminal Walkthrough Demo

A complete end-to-end simulation of Slug in action across two machines:

```text
========================================================================================
[MACHINE A (HOST) - 192.168.1.50] - HOSTING SECURE WORKSPACE
========================================================================================

# Step 1: Host a local project workspace on port 9443 with Suite 3 PurePQC & AI Guard
$ slug add ./lab_workspace -p 9443 -s 3 --ttl 4h -ai --daemon

   _____ _             
  / ____| |            
 | (___ | |_   _  __ _ 
  \___ \| | | | |/ _` |
  ____) | | |_| | (_| |
 |_____/|_|\__,_|\__, |
                  __/ |
                 |___/ 
  Slug: Secure, Ephemeral, Git-like Workspace Sharing & Synchronization
  Version: 1.0.0-rc1 | Post-Quantum Cryptography & AI Guard (Apache-2.0)

[*] Initializing Workspace at: /home/operator/lab_workspace

+----------------------------------------------------------------------------+
| SLUG SECURE WORKSPACE HOSTED SUCCESSFULLY                                  |
+----------------------------------------------------------------------------+
  Port:            9443
  Crypto Suite:    Suite 3: PurePQC (BLAKE3/ML-DSA-65/ML-KEM-768/XChaCha)
  AI Secret Guard: ENABLED (Stateful BLAKE3 Audit)
  Session TTL:     4h
  One-Time TOTP:   49182305 (Rotates in 30s)
  Directory Drop:  http://127.0.0.1:9443/drop
  Admin Dashboard: http://127.0.0.1:9443/admin
+----------------------------------------------------------------------------+
Connect with:  slug connect -i 127.0.0.1 -p 9443 -o 49182305
Sync with:     slug pull ./local_dir -i 127.0.0.1 -p 9443 -o 49182305
+----------------------------------------------------------------------------+

[+] Server running in background (PID: 71204).


# Step 2: Directly inspect a suspicious file with the built-in AI Guard
$ slug audit scan ./lab_workspace/config/secrets.js

[*] Scanning file: ./lab_workspace/config/secrets.js
    Provider: LOCAL_HEURISTIC (Entropy & Heuristics)

[!] SECRET DETECTED BY AI GUARD!
    Line:    14
    Reason:  AWS Access Key ID
    Matched: const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
    Status:  BLOCKED from sync transit.


# Step 3: Add an ephemeral read-write account for team member Alice
$ slug user add -u alice -p "SuperSecurePass_2026" --role rw --ttl 2h -P 9443
[+] User 'alice' added with role rw (TTL: 2h)


========================================================================================
[MACHINE B (CLIENT) - 192.168.1.88] - CONNECTING & SYNCHRONIZING
========================================================================================

# Step 4: Verify connectivity and complete Post-Quantum Handshake with One-Time TOTP
$ slug connect -i 192.168.1.50 -p 9443 -o 49182305

[*] Connecting to 192.168.1.50:9443...
[+] Handshake OK! Negotiated: Suite 3: PurePQC (BLAKE3/ML-DSA-65/ML-KEM-768/XChaCha)
[*] Authenticating with single-use TOTP: 49182305...
[+] Authenticated via TOTP (token burned) | Role: rw | Session ID: 1000

# Notice: Re-running connection with the same TOTP immediately fails (burn-on-use)
$ slug connect -i 192.168.1.50 -p 9443 -o 49182305
[-] Authentication failed: TOTP token invalid, expired, or already burned!


# Step 5: Pull workspace using Git-like Content-Addressable Delta Sync
$ slug pull ./downloaded_workspace -i 192.168.1.50 -p 9443 -u alice -W "SuperSecurePass_2026"

[*] Starting Delta Sync into /home/developer/downloaded_workspace...
Synced: src/main.rs (4.2 KB)
Synced: src/crypto_utils.rs (12.8 KB)
Synced: Cargo.toml (1.1 KB)
Synced: README.md (3.4 KB)
[!] Skipped flagged file: config/secrets.js (AI_FLAGGED: AWS Access Key ID)
Pull complete! Transferred 21.5 KB, saved 0.0 KB (Git-like Delta Sync)


# Step 6: Make changes and push a new feature back to Host Machine A
$ slug push ./downloaded_workspace src/patch.rs -i 192.168.1.50 -p 9443 -u alice -W "SuperSecurePass_2026"
Push successful: src/patch.rs (1.8 KB)


========================================================================================
[LOCAL SECURITY & BENCHMARKING] - RAM-ONLY ENVSHIELD & PERFORMANCE SUITE
========================================================================================

# Step 7: Encrypt sensitive .env file using NIST FIPS 203 Post-Quantum Envelope Encryption
$ slug env init -s 3
[+] Plaintext .env wiped from storage.
[+] Encrypted into .env.pqc using Suite 3: PurePQC (ML-KEM-768/XChaCha20)

# Step 8: Execute application with in-memory secret injection (Zero disk persistence)
$ slug env run -- python3 server.py
[+] Injected 6 environment variables from RAM directly into process
[*] Server listening on port 8080 (Process memory wiped via OPENSSL_cleanse on exit)


# Step 9: Measure cryptographic and transport throughput on your machine
$ slug bench --quick

================================================================================
                 SLUG PERFORMANCE & SECURITY BENCHMARK REPORT                   
================================================================================

[1] CRYPTOGRAPHIC SUITE PERFORMANCE COMPARISON:
SUITE                                 KEM KEYGEN    KEM ENCAP     KEM DECAP     KEM OPS/SEC     
------------------------------------------------------------------------------------------------
Suite 1: Classical (Ed25519/X25519)   104 us        67 us         65 us         4198 ops/s      
Suite 2: Modern (BLAKE3/X25519)       28 us         54 us         53 us         7324 ops/s      
Suite 3: PurePQC (ML-KEM/ML-DSA)      38 us         36 us         96 us         5856 ops/s      

[2] HASH ENGINE SHOOTOUT:
ALGORITHM                         THROUGHPUT (MB/s)     LATENCY (10MB)      
----------------------------------------------------------------------------
BLAKE3 (Tree-hashing / 256-bit)   1051.8 MB/s           4.75 ms             
SHA-256 (OpenSSL EVP)             2312.9 MB/s           2.16 ms             

[3] STATEFUL AI SECRET GUARD & CACHE:
  - Heuristic Scan Throughput: 6.4 MB/s (215698 lines/sec)
  - Stateful Index Cache Hit:  0.015 us / file lookup (0ms overhead on unchanged files)

[4] DELTA SYNC PIPELINE (64 KiB Content-Addressable Chunker):
  - Chunking Throughput:       1047.9 MB/s
  - Chunk Rate:                16767 chunks/sec
================================================================================
```

---

## Quickstart Guide

### 1. Host a Workspace (Host Machine)
```bash
# Share current directory on port 9443 with PurePQC and AI Guard
slug add . -p 9443 -s 3 -ai --daemon
```

### 2. Connect & Synchronize (Client Machine)
```bash
# Test connection with single-use TOTP
slug connect -i 192.168.1.50 -p 9443 -o 84729103

# Pull workspace with Git-like Delta Sync
slug pull ./my_project -i 192.168.1.50 -p 9443 -o 84729103
```

### 3. Ephemeral User Management
```bash
# Add a read-only account valid for 2 hours
slug user add -u bob -p password123 --role r --ttl 2h -P 9443

# Add a read-write account valid for 24 hours
slug user add -u alice -p securePass456 --role rw --ttl 24h -P 9443

# List active accounts and remaining TTL
slug user list -P 9443
```

### 4. Selective Pull & Incremental Update
```bash
# Preview what would be downloaded without saving
slug pull ./my_project -i 192.168.1.50 -p 9443 -u alice -W securePass456 --dry-run

# Only pull C++ files and remove deleted local files
slug pull ./my_project -i 192.168.1.50 -p 9443 -u alice -W securePass456 --ext ".cpp,.hpp" --prune
```

### 5. Upload File (Requires `w` or `rw` role)
```bash
slug push ./local_patch.patch src/patch.patch -i 192.168.1.50 -p 9443 -u alice -W securePass456
```

### 6. Security Rules & AI Audit
```bash
# Block all .key and .pem files
slug rule block --ext .pem -P 9443

# Inspect AI Guard audit status
slug audit list -P 9443

# Whitelist false positive with reason
slug audit allow tests/mock_token.ts --reason "Safe mock secret" -P 9443
```

### 7. PQC EnvShield
```bash
# Encrypt .env -> .env.pqc
slug env init

# Run application with in-memory decrypted environment
slug env run -- python3 app.py
```

### 8. Stop Server
```bash
slug stop -p 9443
```

---

## CLI Command Reference

| Command | Arguments / Flags | Description |
| :--- | :--- | :--- |
| `slug add <path>` | `-p <port>` `-s <suite>` `--ttl <duration>` `-ai` `--daemon` | Host and share workspace |
| `slug status` | `--flagged` | List active workspaces, ports, suites, and flagged files |
| `slug stop` | `-p <port>` | Stop sharing workspace at specified port |
| `slug connect` | `-i <ip> -p <port> -o <totp> \| -u <user> -W <pass>` | Test connection and authenticate |
| `slug pull <dir>` | `-i <ip> -p <port> [--dry-run] [--only <pat>] [--ext <exts>] [--prune]` | Synchronize workspace with Delta Sync |
| `slug push <file> <remote>` | `-i <ip> -p <port> -u <user> -W <pass>` | Upload file to remote workspace |
| `slug user add` | `-u <user> -p <pass> --role <r\|w\|rw> --ttl <ttl> -P <port>` | Create ephemeral workspace account |
| `slug user list` | `-P <port>` | List accounts and remaining session lifetimes |
| `slug user rm` | `-u <user> -P <port>` | Revoke workspace user account |
| `slug rule block` | `--ext <ext> \| --path <path> \| --contains <str> -P <port>` | Add security filter rule to `rules.conf` |
| `slug rule allow` | `--path <path> -P <port>` | Add whitelist path rule |
| `slug rule list` | `-P <port>` | List active security rules |
| `slug audit list` | `-P <port>` | List files flagged or skipped by AI Guard |
| `slug audit allow` | `<path> --reason <desc> -P <port>` | Whitelist false positive |
| `slug audit recheck` | `<path\|--all> -P <port>` | Rescan file(s) and auto-unblock if secret removed |
| `slug env init` | `[-s <suite>]` | Encrypt `.env` into `.env.pqc` with PurePQC |
| `slug env run` | `-- <command...>` | Inject decrypted variables in RAM and execute command |
| `slug bench` | `[--quick] [--json]` | Benchmark crypto suites, BLAKE3, AI Guard, & chunker |
| `slug version` | | Print version and cryptographic build features |

---

## Web GUI & Metrics Dashboard

When hosting a workspace (`slug add`), an embedded Web GUI is available on the same port:
- **Directory Drop (`/drop`)**: Air-drop file explorer to view and download files directly via web browser.
- **Admin & Benchmark Dashboard (`/admin`)**: Interactive dashboard displaying active session TTL, TOTP rotation, security audit logs, and a real-time cryptographic/performance benchmark runner.
- **REST API (`/api/bench`)**: Returns JSON benchmark metrics for automated performance monitoring.

---

## Building from Source

Detailed multi-platform build instructions are available in [BUILD.md](BUILD.md).

### Linux (Universal Static Binary)
```bash
./scripts/build_static.sh
```

### Windows (MSVC or MinGW)
```cmd
.\scripts\build_windows.bat
```
Or in PowerShell:
```powershell
.\scripts\build_windows.ps1
```

### Running Test Suite
```bash
bash scripts/test_local.sh
```

---

## License

Slug is licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) for the full license text.
