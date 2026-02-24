# 🌀 SSX (ShortScan X)

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/Go-1.18%2B-00ADD8?style=flat&logo=go)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)

**SSX** is a high-performance security toolkit and research repository focused on identifying and analyzing **Microsoft IIS Short Filename (8.3 TILDE)** vulnerabilities. It features a sophisticated enumeration engine that reconstructs long filenames from their short equivalents using advanced pattern matching and checksum algorithms.

---

## 🚀 Key Features

*   **⚡ High-Performance Engine**: Concurrent scanning architecture for rapid discovery.
*   **🔍 Smart Reconstruction**: Uses proprietary checksum matching to identify full filenames.
*   **🛠️ Flexible Tooling**: Includes `shortscan` for discovery and `shortutil` for wordlist generation.
*   **📊 Multi-Format Output**: Human-readable terminal output and machine-parsable JSON.
*   **🌐 Broad Target Support**: Scan individual URLs or bulk lists with custom headers.

---

## ⚙️ Installation

### Prerequisites
*   [Go 1.18+](https://golang.org/dl/) installed and configured.

### Quick Install
```bash
go install github.com/bitquark/shortscan/cmd/shortscan@latest
```

### Manual Build
```bash
git clone https://github.com/Serdar715/ssx.git
cd ssx/shortscan
go build -o shortscan ./cmd/shortscan
```

---

## 📖 Usage Guide

### Basic Scan
Perform a quick scan on a single target to identify vulnerable directories:
```bash
shortscan http://target-iis-server.com/
```

### Advanced Enumeration
Customize the scan with specific headers and concurrency levels:
```bash
shortscan -c 50 -t 5 -H "User-Agent: Security-Scanner" http://target.com/
```

### Bulk Scanning
Process multiple URLs from a file:
```bash
shortscan @targets.txt
```

---

## 🛠️ Components

| Component | Description |
| :--- | :--- |
| `shortscan` | The primary CLI tool for short filename enumeration. |
| `shortutil` | A utility for checksum generation and rainbow table creation. |
| `pkg/` | Core library containing the scanning logic and algorithms. |

---

## 🛡️ Security Disclaimer
This tool is intended for legal security auditing and educational purposes only. Unauthorized access to computer systems is illegal. The developers assume no liability for any misuse of this tool.

---

## ⚖️ License
Distributed under the **MIT License**. See `shortscan/LICENSE.md` for more information.

## 🤝 Acknowledgments
*   **Soroush Dalili**: Original IIS short filename vulnerability research.
*   **bitquark**: Original development of the `shortscan` engine.
*   **Serdar715**: Project maintenance and consolidation.

---

<p align="center">
  Developed with ❤️ for the security community.
</p>
