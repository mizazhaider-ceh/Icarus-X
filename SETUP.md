# 🚀 ICARUS-X Setup Guide

Complete installation and setup instructions for ICARUS-X Pentesting Framework.

---

## 📋 Prerequisites

### System Requirements
- **OS:** Linux (Kali/Ubuntu/Debian), macOS, or Windows with WSL2
- **Python:** 3.11 or higher
- **RAM:** 4GB minimum, 8GB recommended
- **Storage:** 2GB minimum

### Required Tools
ICARUS-X integrates with popular pentesting tools:
- **nmap** - Network scanning
- **ffuf** / **gobuster** - Directory brute-forcing  
- **nuclei** - CVE vulnerability scanning
- **httpx** - HTTP probing
- **subfinder** / **amass** - Subdomain enumeration
- **sqlmap** - SQL injection testing
- **nikto** / **whatweb** - Web scanning

---

## 🔧 Installation

### Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/Icarus-X.git
cd Icarus-X
```

### Step 2: Install Python Dependencies

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

**Dependencies installed:**
- `typer` - CLI framework
- `rich` - Terminal UI
- `httpx` - Async HTTP client
- `pydantic` - Data validation
- `aiodns` - Async DNS resolution
- `aiofiles` - Async file operations
- `sqlmodel` - Database ORM
- `jinja2` - Templating for reports
- `cerebras-cloud-sdk` - AI integration (optional, world's fastest)

### Step 3: Install External Tools

#### Kali Linux / Debian / Ubuntu
```bash
# APT packages
sudo apt update
sudo apt install -y nmap ffuf gobuster nuclei nikto sqlmap hydra whatweb amass

# Go tools (requires Go 1.21+)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Python tools
pip install dirsearch
```

#### macOS
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install tools
brew install nmap
brew install ffuf
brew install gobuster

# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

#### Windows (WSL2 Recommended)
```bash
# Use WSL2 with Ubuntu and follow Linux instructions
wsl --install

# After WSL setup:
sudo apt update && sudo apt install -y nmap ffuf gobuster nuclei
```

### Step 4: Verify Installation

```bash
python icarus.py tools
```

This command checks all installed tools and shows installation commands for missing ones.

---

## ⚙️ Configuration

### Environment Variables (Optional)

For AI features, you need a Cerebras API key:

```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your API key
nano .env
```

**.env contents:**
```bash
# Get free API key from: https://inference.cerebras.ai/
ICARUS_AI_API_KEY=your_cerebras_api_key_here
# or
CEREBRAS_API_KEY=your_cerebras_api_key_here
```

### Configuration File

Edit `icarus.toml` to customize behavior:

```toml
[scanner]
port_timeout = 2.0              # Port scan timeout (seconds)
max_concurrent_ports = 500       # Concurrent port scans
default_ports = "top-1000"      # Port preset

[ai]
provider = "cerebras"           # AI provider (world's fastest)
model = "llama3.1-8b"           # Available: llama3.1-8b, llama-3.3-70b, gpt-oss-120b

[logging]
level = "INFO"                  # Log level: INFO, DEBUG, WARNING
log_dir = "./logs"              # Log directory
```

---

## 🧪 Testing Installation

### Test Basic Commands

```bash
# 1. Check tools status
python icarus.py tools

# 2. View available wordlists
python icarus.py wordlists --scan

# 3. Test scout mode (replace with authorized target)
python icarus.py scout --target scanme.nmap.org --ports 22,80,443

# 4. Generate payloads
python icarus.py payloads --list shells
```

### Test AI Features (Optional)

```bash
# Requires CEREBRAS_API_KEY in .env
export $(cat .env | xargs)
python icarus.py ai --query "explain nmap scan types"
```

---

## 🐛 Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'X'"
**Solution:** Ensure virtual environment is activated and dependencies installed
```bash
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

### Issue: "Tool not found" when running commands
**Solution:** Install missing tools using the commands shown by:
```bash
python icarus.py tools
```

### Issue: AI commands fail with "API key not configured"
**Solution:** Set up `.env` file with your Cerebras API key:
```bash
cp .env.example .env
# Edit .env and add: ICARUS_AI_API_KEY=your_key_here
```

### Issue: Permission denied on Linux/macOS
**Solution:** Make the script executable
```bash
chmod +x icarus.py
```

### Issue: "Port scan too slow"
**Solution:** Adjust concurrency in `icarus.toml`:
```toml
[scanner]
max_concurrent_ports = 1000  # Increase for faster scans
```

---

## 🔒 Security Best Practices

1. **Always get authorization** before scanning targets
2. **Use VPN/proxy** when appropriate
3. **Store credentials securely** - never commit `.env` files
4. **Run in isolated environment** - use VMs or containers
5. **Review logs regularly** - check `logs/` directory

---

## 📚 Next Steps

✅ Read the [README.md](README.md) for usage examples  
✅ Check [USAGE.md](USAGE.md) for detailed command documentation  
✅ Review example workflows in `examples/` directory  
✅ Join our community for support and updates  

---

## 🆘 Getting Help

- **Documentation:** [GitHub Wiki](https://github.com/yourusername/Icarus-X/wiki)
- **Issues:** [GitHub Issues](https://github.com/yourusername/Icarus-X/issues)
- **Discord:** [Join our community](#)

---

**Happy Hacking! 🔐**

*Remember: With great power comes great responsibility. Always hack ethically.*
