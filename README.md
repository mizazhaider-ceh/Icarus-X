<div align="center">

# ✈️ ICARUS-X

### Unified AI-Powered Penetration Testing Framework

```
 ___ ____    _    ____  _   _ ____        __  __
|_ _/ ___|  / \  |  _ \| | | / ___|      \ \/ /
 | | |     / _ \ | |_) | | | \___ \  _____\  / 
 | | |___ / ___ \|  _ <| |_| |___) ||_____/  \ 
|___|\\____/_/   \_\_| \_\\___/|____/      /_/\_\
```

**One CLI • Multiple Modes • Blazing Fast Async Operations**

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=for-the-badge)](LICENSE)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen.svg?style=for-the-badge)](https://github.com/mizazhaider-ceh/Icarus-X)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20WSL2-lightgrey.svg?style=for-the-badge)](https://github.com/mizazhaider-ceh/Icarus-X)

[Features](#-features) • [Screenshots](#-screenshots) • [Installation](#-quick-start) • [Usage](#-usage) • [AI Assistant](#-ai-assistant)

---

### 🎬 Demo

![ICARUS-X Demo](screenshots/demo.gif)

</div>

---

## � About

**ICARUS-X** is a modern, unified penetration testing framework designed for security professionals and ethical hackers. Built with Python 3.11+ and leveraging async/await patterns, it delivers exceptional performance in reconnaissance, vulnerability scanning, and attack surface enumeration.

### 🎯 Why ICARUS-X?

- **🚀 Blazing Fast:** Async operations with 500+ concurrent connections
- **🤖 AI-Powered:** Integrated AI assistant for command suggestions and CVE explanations
- **🔧 Unified Interface:** 13+ modules in a single, intuitive CLI
- **📊 Professional Reports:** HTML/Markdown/JSON report generation
- **🔐 Security-First:** No hardcoded credentials, environment-based configuration
- **🎨 Modern UI:** Rich terminal interface with live progress tracking

---

## ✨ Features

### Core Capabilities

| Module | Description | Key Features |
|--------|-------------|--------------|
| 🔍 **Scout** | High-speed reconnaissance | Async port scanning, subdomain enumeration, HTTP probing |
| 🕷️ **Spider** | Web application crawler | Recursive crawling, JS parsing, form detection |
| 🎯 **DirBrute** | Directory brute-forcing | ffuf/gobuster integration, multi-wordlist support |
| 🔬 **Vuln** | Vulnerability scanning | Nuclei CVE detection, template-based scanning |
| 🔧 **Tech** | Technology detection | Wappalyzer integration, framework fingerprinting |
| 💉 **Payloads** | Attack payload generation | XSS, SQLi, shells, command injection, LFI |
| 🌐 **NetMap** | Network discovery | Host enumeration, service detection, CIDR support |
| 🤖 **AI** | AI-powered assistant | Command suggestions, CVE explanations, contextual help |
| 📊 **Report** | Professional reporting | HTML/Markdown/JSON formats, templated output |

### Advanced Features

- **Async Architecture:** 500+ concurrent port scans, 200+ concurrent DNS queries
- **Mass Target Support:** CIDR ranges, IP ranges, target lists from files
- **Wordlist Manager:** Browse 100+ categorized wordlists with intelligent search
- **Tool Checker:** Automatic detection and installation guidance for 14+ tools
- **Database Persistence:** SQLite-based workflow tracking and resumption
- **Modular Design:** Clean separation of concerns, easy to extend

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Linux (Kali/Ubuntu/Debian), macOS, or Windows with WSL2

### Installation

```bash
# Clone repository
git clone https://github.com/mizazhaider-ceh/Icarus-X.git
cd Icarus-X

# Install Python dependencies
pip install -r requirements.txt

# Install external tools (Kali/Ubuntu/Debian)
sudo apt install nmap ffuf gobuster nuclei nikto sqlmap hydra whatweb

# Verify installation
python icarus.py tools
```

**📚 Detailed Setup:** See [SETUP.md](SETUP.md) for comprehensive installation instructions.

---

## 💻 Usage

### Basic Commands

#### 🔍 Reconnaissance (Scout Mode)
```bash
# Fast port scan + HTTP probing
python icarus.py scout --target example.com

# Custom ports
python icarus.py scout --target example.com --ports 22,80,443,8080

# Mass scanning from file
python icarus.py scout --targets targets.txt

# Full reconnaissance with tech detection
python icarus.py scout --target example.com --tech
```

#### 🎯 Directory Brute-forcing
```bash
# Basic directory scan
python icarus.py dirbrute --target https://example.com

# Custom wordlist
python icarus.py dirbrute --target https://example.com --wordlist common.txt

# Multiple extensions
python icarus.py dirbrute --target https://example.com --ext php,html,js
```

#### 🔬 Vulnerability Scanning
```bash
# Nuclei CVE scan
python icarus.py vuln --target https://example.com

# Specific severity
python icarus.py vuln --target https://example.com --severity critical,high

# Save results
python icarus.py vuln --target https://example.com --output vulns.json
```

#### 💉 Payload Generation
```bash
# List all shell payloads
python icarus.py payloads --list shells

# Generate reverse shell
python icarus.py payloads --type bash --ip 10.10.14.5 --port 4444

# XSS payloads
python icarus.py payloads --list xss

# SQLi payloads
python icarus.py payloads --list sqli
```

#### 🤖 AI Assistant (Requires API Key)
```bash
# Get command suggestions
python icarus.py ai --commands --goal "enumerate SMB shares"

# Explain CVE
python icarus.py ai --explain CVE-2024-1234

# General queries
python icarus.py ai --query "how to bypass WAF?"
```

### Advanced Workflows

#### Full Penetration Test
```bash
# Complete workflow: recon → vuln scan → report
python icarus.py pentest --target example.com --workflow full

# Quick scan (faster, less comprehensive)
python icarus.py pentest --target example.com --workflow quick

# Resume previous scan
python icarus.py pentest --run-id abc123
```

#### Report Generation
```bash
# Generate HTML report
python icarus.py report --run-id abc123 --format html

# Markdown export
python icarus.py report --run-id abc123 --format markdown

# JSON for automation
python icarus.py report --run-id abc123 --format json --output results.json
```

#### Manage Workflow Runs
```bash
# List recent scans
python icarus.py runs list --limit 10

# View specific run details
python icarus.py runs show abc123
```

---

## � Screenshots

<details>
<summary><b>🔧 Tool Status Check</b> - Verify all pentesting tools are installed</summary>

<br>

![Tool Status](screenshots/tools-check.png)

```bash
python icarus.py tools
```

</details>

<details>
<summary><b>🔍 Scout Reconnaissance</b> - High-speed async port scanning & enumeration</summary>

<br>

![Scout Scan](screenshots/scout-scan.png)

```bash
python icarus.py scout --target example.com
```

</details>

<details>
<summary><b>📁 Directory Brute-forcing</b> - Discover hidden files and directories</summary>

<br>

![DirBrute](screenshots/dirbrute.png)

```bash
python icarus.py dirbrute --target https://example.com --ext php,html
```

</details>

<details>
<summary><b>🤖 AI Assistant</b> - Get intelligent command suggestions (Powered by Cerebras)</summary>

<br>

![AI Assistant](screenshots/ai-assistant.png)

```bash
python icarus.py ai --commands --goal "enumerate SMB shares"
```

</details>

<details>
<summary><b>💉 Payload Generator</b> - Generate attack payloads for various scenarios</summary>

<br>

![Payloads](screenshots/payloads.png)

```bash
python icarus.py payloads --list shells
```

</details>

> **📝 Adding Screenshots:** Create a `screenshots/` folder and add your terminal screenshots as PNG files.

---

## 🔍 Scout Mode

```bash
python icarus.py scout --target example.com
python icarus.py scout --target example.com --tech   # Include tech detection
python icarus.py scout --targets targets.txt          # Mass target import
```

Features:
- **Async port scanning** (500+ concurrent connections)
- **Subdomain enumeration** (aiodns-powered)
- **HTTP service probing**
- **WHOIS lookups**
- **Technology detection**
- **Multiple output formats**: table, json, csv

---

## 🕷️ Web Spider

```bash
python3 icarus.py spider --target https://example.com
python3 icarus.py spider --target https://example.com --depth 3
```

Discovers:
- Links and endpoints
- Forms and input fields
- JavaScript files
- API endpoints
- Hidden paths

---

## 📁 Directory Brute-forcing

```bash
python3 icarus.py dirbrute --target https://example.com
python3 icarus.py dirbrute --target https://example.com --wordlist medium --ext php,html,txt
python3 icarus.py dirbrute --target https://example.com --threads 100 --tool ffuf
```

Options:
- **Wordlists**: small, medium, large, or custom path
- **Extensions**: Auto-detect or specify (php, html, txt, asp, js)
- **Tools**: ffuf, gobuster, feroxbuster (auto-selects available)
- **Threads**: Configurable concurrency

---

## 🔓 Vulnerability Scanning

```bash
python3 icarus.py vuln --target https://example.com --quick
python3 icarus.py vuln --target https://example.com --severity critical,high
python3 icarus.py vuln --target https://example.com --tags cve,rce,sqli
python3 icarus.py vuln --target https://example.com --output vulns.json
```

Powers Nuclei CVE scanning with:
- **Severity filtering**: critical, high, medium, low
- **Tag-based scanning**: cve, rce, sqli, lfi, ssrf, xss
- **Quick mode**: Critical/high only for fast results
- **JSON output** for further processing

---

## 🔬 Technology Detection

```bash
python3 icarus.py tech --target https://example.com
```

Fingerprints:
- **Web servers**: nginx, Apache, IIS, Caddy
- **CMS**: WordPress, Drupal, Joomla, Magento
- **Frameworks**: React, Vue, Angular, Django, Laravel
- **CDN & Security**: Cloudflare, Akamai, AWS
- **Databases**: MySQL, PostgreSQL indicators
- **Version detection** where available

---

## 🌐 Network Discovery

```bash
python3 icarus.py netmap --range 192.168.1.0/24
python3 icarus.py netmap --quick                    # Auto-detect network
python3 icarus.py netmap --range 10.0.0.0/24 --tree # Tree view
```

Features:
- Host discovery (ping sweep)
- Port scanning
- Device fingerprinting
- MAC vendor lookup
- Network topology visualization

---

## ⚔️ Payload Generator

```bash
python3 icarus.py payloads --list xss      # XSS payloads
python3 icarus.py payloads --list sqli     # SQL injection payloads
python3 icarus.py payloads --list cmdi     # Command injection
python3 icarus.py payloads --list shells   # Reverse shell one-liners
python3 icarus.py payloads --list traversal # Path traversal
python3 icarus.py payloads --encoder base64 --list xss
```

Payload Types:
- **XSS**: Alert, cookie stealing, DOM-based
- **SQLi**: Union, boolean, time-based, stacked
- **Command Injection**: Linux/Windows
- **Reverse Shells**: Bash, Python, PHP, Netcat, PowerShell
- **Path Traversal**: Linux/Windows variants
- **Encoders**: base64, url, html

---

## 🎯 Full Pentest Workflow

```bash
python3 icarus.py pentest --target example.com
python3 icarus.py pentest --target example.com --workflow quick
python3 icarus.py pentest --target example.com --workflow full --verbose
python3 icarus.py pentest --run-id abc123         # Resume
```

Workflows:
- **quick**: Fast scan (recon + basic vuln)
- **full**: Complete workflow (recon → vuln → exploit → post)
- **recon-only**: Just reconnaissance

All results are persisted to database for resumption.

---

## 🤖 AI Assistant

```bash
export CEREBRAS_API_KEY=your-key

# Command suggestions
python3 icarus.py ai --commands --goal "enumerate SMB shares"
python3 icarus.py ai --commands --goal "privilege escalation on Linux"

# Explain vulnerabilities
python3 icarus.py ai --explain CVE-2024-1234

# General queries
python3 icarus.py ai --query "how to bypass WAF?"
```

Requires Cerebras API key (free tier available - world's fastest AI inference at up to 3000 tokens/s).

---

## 📊 Reports

```bash
python3 icarus.py report --run-id abc123 --format html
python3 icarus.py report --run-id abc123 --format markdown
python3 icarus.py report --run-id abc123 --format json
```

---

## 📂 Mass Target Import

```bash
python3 icarus.py scout --targets targets.txt
```

**targets.txt format:**
```
192.168.1.1
192.168.1.0/24       # CIDR notation
192.168.1.1-50       # IP range
example.com
https://example.com
```

---

## ⚙️ Configuration

Edit `icarus.toml`:
```toml
[scanner]
port_timeout = 2.0
max_concurrent_ports = 500
default_ports = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443"

[ai]
provider = "cerebras"
model = "llama3.1-8b"

[report]
template_dir = "templates"
output_dir = "reports"
```

---

## 🛠️ Required Tools

**Quick Install (Kali/Debian):**
```bash
sudo apt install nmap ffuf gobuster nuclei nikto sqlmap hydra whatweb feroxbuster amass
```

**Go Tools:**
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Check Status:**
```bash
python3 icarus.py tools
```

---

## 📁 Project Structure

```
icarus_x/
├── icarus.py           # Main CLI entry point
├── icarus.toml         # Configuration file
├── core/               # Core engine modules
│   ├── scanner.py      # Async reconnaissance engine
│   ├── workflow.py     # Workflow orchestration
│   ├── reporter.py     # Report generation
│   └── ai_engine.py    # AI integration (Cerebras)
├── modules/            # Feature modules
│   ├── dirbrute.py     # Directory brute-forcing
│   ├── nuclei.py       # CVE scanning
│   ├── techdetect.py   # Technology detection
│   ├── spider.py       # Web crawling
│   ├── netmap.py       # Network discovery
│   ├── payloads.py     # Payload generation
│   └── targets.py      # Mass target import
├── models/             # Data models
│   ├── target.py       # Target schema
│   ├── finding.py      # Finding schema
│   └── run.py          # Workflow run schema
└── utils/              # Utilities
    ├── tools.py        # Tool checker
    ├── wordlists.py    # Wordlist manager
    ├── config.py       # Configuration
    └── logger.py       # Logging
```

---

## 🔒 Security & Legal

> ⚠️ **ICARUS-X is designed for authorized security testing only.**

Always ensure you have:
- Written authorization from the target owner
- Proper scope definitions
- Understanding of local laws

Unauthorized scanning is illegal and unethical.

---

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.

---

**ICARUS-X v2.0** - *Fly high, but not too close to the sun* ☀️

Built with ❤️ using Python, asyncio, Typer, Rich, and Cerebras AI
