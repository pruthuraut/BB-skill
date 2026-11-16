# Environment Setup & Tool Installation Guide

This guide provides end-to-end setup instructions, download commands, and configuration details required to execute the **Bug Bounty Multi-Agent Skills Framework** and the **`recon-hunter` 16-Phase Pipeline** smoothly.

---

## 1. Quick Start (Automated One-Click Setup)

For **Ubuntu**, **Debian**, **Kali Linux**, or **WSL2 (Windows Subsystem for Linux)**, an automated installation script is provided in the repository root:

```bash
# Make script executable and run
chmod +x setup.sh
./setup.sh
```

The script automatically installs system packages, verifies/installs Go, downloads all Go engines, installs Python security tools in the repository-local `.venv`, compiles `massdns`, updates Nuclei templates, creates a verified `resolvers.txt`, and runs a health-check verification matrix.

The installer is safe to rerun after an interrupted download: tools already available in `PATH` are skipped. If setup stops, fix the reported command and run `./setup.sh` again. The script never falls back to system-wide `pip`, so Kali/Debian's PEP 668 protection remains intact.

After installation, activate the Python tools in each new shell:

```bash
source .venv/bin/activate
```

---

## 2. Prerequisites & Environment Variables

Ensure your shell configuration (`~/.bashrc` or `~/.zshrc`) includes the Go and user binary directories:

```bash
export GOPATH="$HOME/go"
export PATH="$PATH:/usr/local/go/bin:$GOPATH/bin:$HOME/.local/bin:/usr/local/bin"
```

Reload your environment:
```bash
source ~/.bashrc
```

---

## 3. Comprehensive Tool Download & Installation Catalog

If installing manually or on custom distributions, install the tools by category below:

### Category A: Core Linux Packages & Compilers
```bash
sudo apt-get update -y && sudo apt-get install -y \
  curl wget git jq python3 python3-pip python3-venv pipx \
  build-essential libpcap-dev nmap whois dnsutils libssl-dev \
  make gcc unzip tar bsdmainutils chromium
```

---

### Category B: High-Throughput Go Reconnaissance Engines
Install with Go (version >= 1.21 required):

```bash
# --- ProjectDiscovery Suite ---
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
go install -v github.com/projectdiscovery/alterx/cmd/alterx@latest

# --- Active Crawlers & URL Harvesters ---
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/tomnomnom/unfurl@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/hakluke/hakrawler@latest
go install -v github.com/jaeles-project/gospider@latest

# --- Fuzzing, Takeovers, Fingerprinting & Visuals ---
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/glebarez/cero@latest
go install -v github.com/gwen001/github-subdomains@latest
go install -v github.com/haccer/subjack@latest
go install -v github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest
go install -v github.com/sensepost/gowitness@latest
```

---

### Category C: Python Security & Parameter Mining Tools
Install in the project-local virtual environment created by `setup.sh`. Do not use `sudo pip`, `pip install --user`, or `--break-system-packages` on Kali/Debian:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

```bash
# Arjun (Hidden parameter discovery)
.venv/bin/pip install arjun

# Wafw00f (WAF detection)
.venv/bin/pip install wafw00f

# Waymore (Multi-engine historical archive mining)
.venv/bin/pip install waymore

# Dnsvalidator (High-speed DNS resolver validator)
.venv/bin/pip install git+https://github.com/vortexau/dnsvalidator.git

# Knockpy (subdomain enumeration; do not install the unrelated `knockpy` PyPI package)
.venv/bin/pip install git+https://github.com/guelfoweb/KnockPy.git

# ParamSpider (Parameter mining from Web Archives)
git clone https://github.com/devanshbatham/ParamSpider.git /tmp/ParamSpider
.venv/bin/pip install /tmp/ParamSpider
rm -rf /tmp/ParamSpider

# JS Beautifier (for deobfuscating and beautifying JavaScript)
.venv/bin/pip install jsbeautifier
```

---

### Category D: Native Binaries & Source Compilations

#### 1. MassDNS (High-Speed DNS Stub Resolver)
Required by `shuffledns` and `subdomainenum` for mass wildcard filtering and sub-second resolution:
```bash
git clone https://github.com/blechschmidt/massdns.git /tmp/massdns
cd /tmp/massdns && make -j$(nproc)
sudo cp bin/massdns /usr/local/bin/
cd - && rm -rf /tmp/massdns
```

#### 2. TruffleHog (Cryptographic Secret Verification Engine)
Official binary installation:
```bash
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin
```

#### 3. Gitleaks (Fast Static Secret Scanner)
```bash
GITLEAKS_VER="8.18.2"
wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_linux_x64.tar.gz" -O /tmp/gitleaks.tar.gz
tar -xzf /tmp/gitleaks.tar.gz -C /tmp/
sudo mv /tmp/gitleaks /usr/local/bin/
rm -f /tmp/gitleaks.tar.gz
```

#### 4. GitHub Official CLI (`gh`)
Used for organization-wide repository discovery in `cloud-supplychain` (Subagent 02):
```bash
type -p curl >/dev/null || sudo apt-get install curl -y
curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg
sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null
sudo apt-get update && sudo apt-get install gh -y
```

---

### Category E: Added Audit Tools (checklist expansion)
`setup.sh` installs these in Steps 1, 3, 4, and 8c. Run them manually only if the installer reports a failure.

```bash
# Go (STEP 3): subdomain and permutation
go install github.com/PentestPad/subzy@latest
go install github.com/Josue87/gotator@latest
go install github.com/owasp-amass/amass/v4/cmd/amass@master
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest

# Python venv (STEP 4)
.venv/bin/pip install git-dumper sqlmap sslyze
.venv/bin/pip install git+https://github.com/darkoperator/dnsrecon.git

# Apt (STEP 1)
sudo apt-get install -y nikto whatweb

# Scripts with wrappers in ~/.local/bin (STEP 8c)
git clone https://github.com/ticarpi/jwt_tool.git ~/tools/jwt_tool       # jwt_tool.py + requirements.txt
git clone https://github.com/drwetter/testssl.sh.git ~/tools/testssl.sh  # testssl.sh
git clone https://github.com/defparam/smuggler.git ~/tools/smuggler      # smuggler.py

# SSTImap (STEP 8c): detection mode for ssti-audit
git clone https://github.com/vladko312/SSTImap.git ~/tools/SSTImap

# Optional (STEP 8c)
cargo install x8        # hidden parameter discovery (needs Rust)
gem install wpscan      # WordPress plugin and theme data (needs Ruby)
```

---

### Category F: Kali Tools Used by the Skills
`setup.sh` installs these from Kali's repositories (best effort, one package at a time) or via Go, pip, and the optional cargo step:

```bash
sudo apt-get install -y dnsutils dnsrecon dnsenum fierce commix sqlmap wafw00f nmap openssl \
  hashcat gobuster dirsearch feroxbuster dalfox libimage-exiftool-perl ldap-utils netcat-openbsd gh
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
go install github.com/assetnote/kiterunner/cmd/kr@latest   # binary is `kr` (kiterunner)
.venv/bin/pip install degoogle flask-unsign
```

Manual (not installed automatically):

- **Burp Suite**: GUI application, install from PortSwigger. Several checklists reference its Sequencer and Intruder workflows.
- **ysoserial and PHPGGC**: gadget-chain generators for lab use only, referenced by the deserialization checklists (authorized-only). Install them only in an isolated lab.
- **slackcat**: optional Slack alerting used by the jsrecon subagent (guarded by `command -v`).
- **websocat**: installed by `setup.sh` when cargo is present, otherwise install it manually.
- **noseyparker**: installed by `setup.sh` when cargo is present; used by cloud-supplychain secret hunts.

---

## 4. API Keys & Configuration Setup

Passive OSINT tools achieve exponentially higher coverage when supplied with free API keys.

### 1. Subfinder Provider Configuration
Create or edit `~/.config/subfinder/provider-config.yaml`:

```yaml
binaryedge: []
censys:
  - "<CENSYS_API_ID>:<CENSYS_SECRET>"
certspotter: []
chaos:
  - "<CHAOS_API_KEY>"
chinaz: []
dnsdb: []
fofa:
  - "<FOFA_EMAIL>:<FOFA_KEY>"
github:
  - "<GITHUB_PERSONAL_ACCESS_TOKEN>"
intelx: []
passivetotal:
  - "<PASSIVETOTAL_USER>:<PASSIVETOTAL_KEY>"
robtex: []
securitytrails:
  - "<SECURITYTRAILS_API_KEY>"
shodan:
  - "<SHODAN_API_KEY>"
virustotal:
  - "<VIRUSTOTAL_API_KEY>"
whoisxmlapi: []
zoomeye: []
```

### 2. Shell Environment Variables
Export these in your `~/.bashrc` or session:

```bash
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export CHAOS_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export SHODAN_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
export SECURITYTRAILS_API_KEY="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

---

## 5. Wordlists & Resolvers Setup

### 1. Repository Wordlists
This repository includes a consolidated `wordlists/` directory indexed in `wordlists/README.md`:
- `wordlists/params.txt` (Curated parameter names)
- `wordlists/MiniFuzz.txt` & `wordlists/God-Fuzz.txt` (Paths & directories)
- `wordlists/api.txt`, `wordlists/SwaggerAPI.txt`, `wordlists/API-FUZZ.txt` (APIs)
- `wordlists/env.txt`, `wordlists/config.txt`, `wordlists/git_config.txt` (Configs & secrets)

### 2. SecLists (Optional Global Wordlists)
If SecLists is not already installed on your system:
```bash
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists
```

### 3. DNS Resolvers Pool
Generate an updated list of valid DNS resolvers:
```bash
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o ~/resolvers.txt
```

---

## 6. One-Liner Health-Check & Verification

Run this one-liner to verify that all critical tools are available in your `$PATH`:

```bash
for tool in subfinder httpx dnsx naabu alterx katana nuclei shuffledns massdns ffuf waybackurls gau waymore hakrawler gospider trufflehog gitleaks cero subjack subzy gotator amass chaos gowitness fingerprintx interactsh-client arjun x8 wafw00f nmap masscan whatweb nikto sqlmap sslyze dnsrecon git-dumper testssl.sh jwt_tool sstimap jq curl gh; do
  which "$tool" &>/dev/null && echo -e "\e[32m[+] $tool: INSTALLED\e[0m" || echo -e "\e[31m[-] $tool: MISSING\e[0m"
done
```

---

## 7. Running the Framework

Once the setup is verified, you can invoke any skill or execute the master pipeline:

- **Full 16-Phase Pipeline:** Hand a target domain to the assistant with keywords like `"recon target.com"`, `"map attack surface"`, or `"find bugs"`. The system will activate [recon-hunter](.agents/skills/recon-hunter/SKILL.md).
- **Targeted Deep Dives:** Call individual skills as needed:
  - [subdomainenum](.agents/skills/subdomainenum/SKILL.md) (50 Checks)
  - [techfingerprint](.agents/skills/techfingerprint/SKILL.md) (40 Checks)
  - [contentdiscovery](.agents/skills/contentdiscovery/SKILL.md) (50 Checks)
  - [linkparamdiscovery](.agents/skills/linkparamdiscovery/SKILL.md) (40 Checks)
  - [jsrecon](.agents/skills/jsrecon/SKILL.md) (JS De-minification & Secrets)
  - [cloud-supplychain](.agents/skills/cloud-supplychain/SKILL.md) (S3/GCS/Azure/Firebase & Dependency Confusion)
  - [api-security](.agents/skills/api-security/SKILL.md) (Swagger, GraphQL & CORS)
  - [ssrf-audit](.agents/skills/ssrf-audit/SKILL.md) (SSRF & IMDS)
