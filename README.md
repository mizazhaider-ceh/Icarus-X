# ICARUS-X: Unified AI-Powered Pentesting Framework

```
 ___ ____    _    ____  _   _ ____        __  __
|_ _/ ___|  / \  |  _ \| | | / ___|      \ \/ /
 | | |     / _ \ | |_) | | | \___ \  _____\  / 
 | | |___ / ___ \|  _ <| |_| |___) ||_____/  \ 
|___|\\____/_/   \_\_| \_\\___/|____/      /_/\_\
```

**One CLI. Multiple Modes. Blazing Fast.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 🚀 Quick Start

```bash
cd icarus_x

# Install dependencies
pip3 install typer rich httpx pydantic pydantic-settings aiodns aiofiles sqlmodel aiosqlite jinja2 orjson python-whois google-generativeai

# Check installed tools
python3 icarus.py tools

# Fast reconnaissance
python3 icarus.py scout --target scanme.nmap.org

# Full pentest workflow
python3 icarus.py pentest --target example.com
```

---

## 📋 All Commands

| Command | Description |
|---------|-------------|
| `tools` | Check installed pentesting tools (nmap, ffuf, nuclei, etc.) |
| `wordlists` | Browse and find wordlists for fuzzing |
| `scout` | High-speed async reconnaissance |
| `spider` | Web application crawling |
| `dirbrute` | Directory brute-forcing (ffuf/gobuster) |
| `vuln` | Nuclei CVE vulnerability scanning |
| `tech` | Technology detection & fingerprinting |
| `netmap` | Network discovery & host mapping |
| `payloads` | Generate attack payloads (XSS, SQLi, shells) |
| `pentest` | Full workflow orchestration |
| `ai` | AI-powered command suggestions |
| `report` | Generate HTML/Markdown reports |
| `runs` | Manage workflow runs |

---

## 🔧 Tool Checker

```bash
python3 icarus.py tools
```

Checks for required security tools:
- **Network**: nmap, httpx
- **Fuzzing**: ffuf, gobuster, feroxbuster, dirsearch
- **Scanning**: nuclei, nikto, whatweb
- **Exploitation**: sqlmap, hydra
- **Discovery**: subfinder, amass

Shows install commands for any missing tools.

---

## 📚 Wordlist Manager

```bash
python3 icarus.py wordlists --scan              # Scan all wordlist folders
python3 icarus.py wordlists --category dir      # Filter by category
python3 icarus.py wordlists --search rockyou    # Search for wordlists
python3 icarus.py wordlists --path common       # Get path for a wordlist
python3 icarus.py wordlists --locations         # Show all folder locations
```

Categories:
- Directory Bruteforce
- Subdomain Enumeration
- Password Attacks
- Username Enumeration
- Fuzzing (LFI, SQLi, XSS)
- API Testing
- Technology Specific (CMS paths)

---

## 🔍 Scout Mode (Reconnaissance)

```bash
python3 icarus.py scout --target example.com
python3 icarus.py scout --target example.com --ports 22,80,443,8080
python3 icarus.py scout --target example.com --tech   # Include tech detection
python3 icarus.py scout --targets targets.txt          # Mass target import
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
export GEMINI_API_KEY=your-key

# Command suggestions
python3 icarus.py ai --commands --goal "enumerate SMB shares"
python3 icarus.py ai --commands --goal "privilege escalation on Linux"

# Explain vulnerabilities
python3 icarus.py ai --explain CVE-2024-1234

# General queries
python3 icarus.py ai --query "how to bypass WAF?"
```

Requires Google Gemini API key (free tier available).

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
provider = "gemini"
model = "gemini-1.5-flash"

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
│   └── ai_engine.py    # AI integration (Gemini)
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

Built with ❤️ using Python, asyncio, Typer, and Rich
