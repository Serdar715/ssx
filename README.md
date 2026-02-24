<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version"/>
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-lightgrey?style=for-the-badge" alt="Platform"/>
  <img src="https://img.shields.io/badge/CVE-2025--46294-red?style=for-the-badge" alt="CVE"/>
</p>

<h1 align="center">🌀 SSX — IIS Short Filename Scanner</h1>

<p align="center">
  <b>Advanced IIS 8.3 Tilde Enumeration Tool &amp; Security Research Toolkit</b><br/>
  Multi-layer detection · Concurrent scanning · REST API · 6 output formats
</p>

---

## 📑 Table of Contents

- [What is the IIS Tilde Vulnerability?](#-what-is-the-iis-tilde-vulnerability)
- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Full CLI Reference](#-full-cli-reference)
- [Detection Modes](#-detection-modes)
- [Output Formats](#-output-formats)
- [Proxy & Rate Limiting](#-proxy--rate-limiting)
- [REST API](#-rest-api)
- [Utility Tool: shortutil](#-utility-tool-shortutil)
- [Security Disclaimer](#️-security-disclaimer)
- [Credits](#-credits)

---

## 🔍 What is the IIS Tilde Vulnerability?

Microsoft IIS (Internet Information Services) exposes a legacy Windows feature called **8.3 short filenames** (also known as the tilde vulnerability). When enabled, IIS reveals abbreviated versions of long filenames to unauthenticated HTTP requests using wildcard patterns like `*~1*`.

**Example:**
| Long filename | 8.3 Short name |
|---|---|
| `web.config` | `WEBCON~1.CON` |
| `appsettings.json` | `APPSETT~1.JSO` |
| `admin_panel_backup.aspx` | `ADMIN_~1.ASP` |

An attacker can enumerate these short names through HTTP requests and reconstruct hidden file paths — revealing configuration files, backup files, admin panels, and credentials — **without authentication**.

**CVE:** [CVE-2025-46294](https://nvd.nist.gov/vuln/detail/CVE-2025-46294) · **CVSS:** Up to 7.5 (High)

---

## ✨ Features

| Category | Capability |
|---|---|
| **Detection** | 6 detection modes: method, status, distance, timing, fuzzy, auto |
| **Enumeration** | Recursive 8.3 short filename & directory discovery |
| **Performance** | Configurable concurrency, connection pooling, HTTP/2 support |
| **Proxy** | Single proxy, proxy rotation from file, per-proxy failure tracking |
| **Rate Limiting** | Token-bucket rate limiter (requests/sec) |
| **Output** | Human, JSON, CSV, HTML, Markdown, XML |
| **API** | Built-in REST API server for tool chaining & automation |
| **Reliability** | Context-aware cancellation, graceful Ctrl+C shutdown |
| **Checksums** | Rainbow table matching for full filename reconstruction |

---

## ⚙️ Installation

### Option 1 — Build from Source (Recommended)

```bash
git clone https://github.com/Serdar715/ssx.git
cd ssx/shortscan/v2
go build -o ssx ./cmd/ssx

# Install globally (Linux/macOS)
sudo cp ssx /usr/local/bin/ssx

# Windows — copy to any directory in your PATH
copy ssx.exe C:\Windows\System32\ssx.exe
```

### Option 2 — Go Install

```bash
go install github.com/Serdar715/ssx/shortscan/v2/cmd/ssx@latest
```

> **Note:** `go install` fetches the binary via the Go module proxy. If you get a module path error, use Option 1 (build from source) instead.
>
> Make sure `$(go env GOPATH)/bin` is in your `PATH`:
> ```bash
> export PATH=$PATH:$(go env GOPATH)/bin
> ```

### Install utility tool (`shortutil`)

```bash
cd ssx/shortscan
go build -o shortutil ./cmd/shortutil
sudo cp shortutil /usr/local/bin/shortutil
```

**Requirements:** Go 1.21+

---

## 🚀 Quick Start

```bash
# Check if a server is vulnerable
ssx -V http://target.com/

# Full scan with file enumeration
ssx http://target.com/

# Scan with JSON output saved to file
ssx -o json -O results.json http://target.com/

# Bulk scan from a file
ssx @targets.txt

# High-speed scan with 50 threads
ssx -c 50 -t 5 http://target.com/
```

---

## 📋 Full CLI Reference

```
Usage: ssx [OPTIONS] URL [URL...]

Positional Arguments:
  URL          Target URL(s) to scan. Use @ prefix to read from a file (e.g., @targets.txt)

Scan Options:
  -w, --wordlist FILE      Custom wordlist file for full filename reconstruction
  -r, --rainbow FILE       Rainbow table file for checksum-based matching

HTTP Options:
  -H, --header HEADER      Custom HTTP header, repeatable (e.g., -H "Cookie: session=abc")
  -c, --concurrency N      Number of concurrent requests [default: 20]
  -t, --timeout N          Per-request timeout in seconds [default: 10]
      --rate-limit N       Maximum requests per second [default: 100]

Proxy Options:
  -x, --proxy URL          Proxy URL (e.g., http://127.0.0.1:8080, socks5://127.0.0.1:1080)
      --proxy-file FILE    File with proxy URLs for round-robin rotation (one per line)

Detection Options:
  -d, --detection MODE     Detection mode: auto|method|status|distance|timing|fuzzy|none [default: auto]
  -C, --characters CHARS   Characters to enumerate in filenames [default: JFKGOTMYVHSPCANDXLRWEBQUIZ8549176320-_()&'!#$%@^{}~]
  -s, --stabilize          Enable result stabilization for unstable servers (more requests)
  -p, --patience N         Patience level: 0=patient, 1=very patient (more method/path combos) [default: 0]

Scan Behaviour:
  -n, --no-recurse         Disable recursive subdirectory scanning
  -V, --vuln-check         Only check vulnerability status, skip file enumeration
      --deep               Enable deep scanning mode (more thorough, slower)

Output Options:
  -o, --output FORMAT      Output format: human|json|csv|html|markdown|xml [default: human]
  -O, --output-file FILE   Write output to file instead of stdout
  -F, --full-url           Display full URLs instead of short filenames only
  -q, --quiet              Suppress all output except results
  -v, --verbose N          Verbosity level: 0=warn, 1=info, 2=debug [default: 0]

Advanced Options:
      --http2              Enable HTTP/2 support [default: true]
      --insecure           Skip TLS certificate verification [default: true]
      --timing             Enable timing-based anomaly detection [default: true]
      --fuzzy              Enable fuzzy response matching [default: true]

API Server:
      --api                Start the built-in REST API server
      --api-port N         API server port [default: 8080]

Info:
  -h, --help               Show this help and exit
      --version            Show version and exit
```

---

## 🔬 Detection Modes

SSX uses multiple layers of detection to identify vulnerable IIS servers:

| Mode | Description | Best Used When |
|---|---|---|
| `auto` | Automatically selects the best method | Default — recommended for most targets |
| `method` | Uses HTTP method differences (OPTIONS, HEAD, etc.) | Server responds differently to HTTP methods |
| `status` | Compares HTTP status codes (200 vs 404) | Classic IIS tilde vulnerability pattern |
| `distance` | Levenshtein distance on response bodies | Server returns similar content for all paths |
| `timing` | Statistical timing anomaly detection | All status codes are identical |
| `fuzzy` | Fuzzy body comparison with similarity ratio | Generic WAF or filtering present |
| `none` | Disable vulnerability detection, enumerate only | Already confirmed vulnerable |

```bash
# Force a specific detection mode
ssx -d method http://target.com/
ssx -d timing http://target.com/

# Very thorough scan (patience level 1 = all methods × all path suffixes)
ssx --patience 1 http://target.com/
```

---

## 📤 Output Formats

### Human (default) — coloured terminal output
```bash
ssx http://target.com/
```

### JSON — machine-readable, full detail
```bash
ssx -o json http://target.com/
ssx -o json -O scan.json http://target.com/     # save to file
```

### CSV — spreadsheet / SIEM import
```bash
ssx -o csv -O results.csv @targets.txt
```

### HTML — self-contained report
```bash
ssx -o html -O report.html http://target.com/
```

### Markdown — documentation / tickets
```bash
ssx -o markdown http://target.com/
```

### XML — enterprise tool integration
```bash
ssx -o xml -O output.xml http://target.com/
```

---

## 🌐 Proxy & Rate Limiting

```bash
# Route through Burp Suite
ssx -p http://127.0.0.1:8080 http://target.com/

# Route through SOCKS5
ssx -p socks5://127.0.0.1:1080 http://target.com/

# Rotate through a proxy list (proxies.txt, one per line)
ssx --proxy-file proxies.txt http://target.com/

# Limit to 10 requests per second (avoid WAF triggers)
ssx --rate-limit 10 http://target.com/

# Combined: rate limited + proxy
ssx --rate-limit 5 -p http://127.0.0.1:8080 http://target.com/
```

**proxy-file format:**
```
http://proxy1:8080
http://proxy2:3128
socks5://proxy3:1080
# lines starting with # are ignored
```

---

## 🔌 REST API

SSX includes a built-in REST API for integration with automation pipelines and other security tools.

### Start the API server
```bash
ssx --api --api-port 8080 http://placeholder.com/
```

### Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/scan` | Full scan with enumeration |
| `POST` | `/api/v1/detect` | Quick vulnerability check only |
| `GET` | `/api/v1/status` | Scanner statistics |
| `GET` | `/api/v1/health` | Health check (no auth required) |

### Example: Scan via API
```bash
curl -X POST http://localhost:8080/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"urls": ["http://target.com/", "http://target2.com/"]}'
```

**Response:**
```json
{
  "success": true,
  "message": "scanned 2 targets",
  "results": [
    {
      "target_url": "http://target.com/",
      "vulnerable": true,
      "files_discovered": [
        { "short_name": "WEBCON~1.CON", "confidence": 0.95 }
      ]
    }
  ]
}
```

### Example: Quick Detect via API
```bash
curl -X POST http://localhost:8080/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"urls": ["http://target.com/"]}'
```

### API Authentication (optional)
Set `--api-key` in config to require `X-API-Key` header on all requests (except `/health`).

---

## 🛠️ Utility Tool: `shortutil`

The `shortutil` utility generates checksums and rainbow tables for full filename reconstruction.

### Generate a checksum
```bash
shortutil checksum index.html
# → INDEX~1.HTM  (Checksum: 4F2A)
```

### Build a rainbow table from a wordlist
```bash
shortutil wordlist /usr/share/wordlists/dirb/common.txt > rainbow.txt
```

### Use the rainbow table with ssx
```bash
ssx -r rainbow.txt http://target.com/
```

---

## ⚖️ License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

## 🤝 Credits

| Person | Contribution |
|---|---|
| [Soroush Dalili](https://soroush.secproject.com/) | Original IIS tilde vulnerability research & whitepaper |
| [bitquark](https://github.com/bitquark) | Original `shortscan` engine development |
| [Serdar715](https://github.com/Serdar715) | SSX v2 — full refactor, API, multi-mode detection, concurrent architecture |

---

## 🛡️ Security Disclaimer

> This tool is provided for **authorized security assessments, penetration testing, and educational research only**.  
> Scanning systems without explicit written permission is **illegal** and may violate computer crime laws.  
> The authors accept **no liability** for misuse of this software.

---

<p align="center">
  Built for the security community with ❤️ · <a href="https://github.com/Serdar715/ssx/issues">Report an issue</a>
</p>
