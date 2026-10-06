#!/usr/bin/env bash
# ==============================================================================
# Bug Bounty Multi-Agent Skills Framework — Automated Environment Setup Script
# Supported Platforms: Ubuntu / Debian / Kali Linux / WSL2
# ==============================================================================

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

trap 'echo -e "\n${RED}[ERROR] Setup stopped at line ${LINENO}: ${BASH_COMMAND}${NC}" >&2' ERR

echo -e "${CYAN}${BOLD}"
echo "================================================================================"
echo "    BUG BOUNTY MULTI-AGENT FRAMEWORK — ENVIRONMENT & TOOLING SETUP            "
echo "================================================================================"
echo -e "${NC}"

# Detect OS
if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS=$ID
else
  OS=$(uname -s)
fi

echo -e "${BLUE}[*] Detected operating system:${NC} $OS"

# ------------------------------------------------------------------------------
# STEP 1: Core System Dependencies
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Step 1/8] Installing core system packages and build tools...${NC}"

if command -v apt-get &>/dev/null; then
  sudo apt-get update -y
  sudo apt-get install -y \
    curl \
    wget \
    git \
    jq \
    python3 \
    python3-pip \
    python3-venv \
    pipx \
    build-essential \
    libpcap-dev \
    nmap \
    masscan \
    whois \
    dnsutils \
    libssl-dev \
    libffi-dev \
    make \
    gcc \
    unzip \
    tar \
    bsdmainutils
else
  echo -e "${YELLOW}[!] Non-Debian system detected. Please ensure curl, git, jq, nmap, libpcap-dev are installed.${NC}"
fi

# Ensure pipx path
pipx ensurepath 2>/dev/null || true
export PATH="$HOME/.local/bin:$PATH"

# ------------------------------------------------------------------------------
# STEP 2: Golang Environment Setup
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Step 2/8] Verifying Golang installation...${NC}"

if ! command -v go &>/dev/null; then
  echo -e "${YELLOW}[*] Go not found. Installing latest stable Golang...${NC}"
  GO_VERSION="1.22.4"
  ARCH=$(uname -m)
  case $ARCH in
    x86_64) GO_ARCH="amd64" ;;
    aarch64|arm64) GO_ARCH="arm64" ;;
    *) GO_ARCH="amd64" ;;
  esac
  
  wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf /tmp/go.tar.gz
  rm -f /tmp/go.tar.gz
  
  echo 'export PATH=$PATH:/usr/local/go:$HOME/go/bin' >> ~/.bashrc
  export PATH=$PATH:/usr/local/go:$HOME/go/bin
fi

# Setup GOPATH and PATH for current session
export GOPATH="$HOME/go"
export PATH="$PATH:/usr/local/go/bin:$GOPATH/bin:$HOME/.local/bin"

echo -e "${GREEN}[+] Go version: $(go version)${NC}"

# ------------------------------------------------------------------------------
# STEP 3: ProjectDiscovery & High-Performance Go Recon Tools
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Step 3/8] Installing ProjectDiscovery & core Go reconnaissance engines...${NC}"

GO_TOOLS=(
  # ProjectDiscovery Suite
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/projectdiscovery/katana/cmd/katana@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
  "github.com/projectdiscovery/alterx/cmd/alterx@latest"

  # Fast Crawlers, Historical & URL Harvesters
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/tomnomnom/unfurl@latest"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/hakluke/hakrawler@latest"
  "github.com/jaeles-project/gospider@latest"

  # Fuzzing & Protocol Tools
  "github.com/ffuf/ffuf/v2@latest"
  "github.com/sensepost/gowitness@latest"
  "github.com/glebarez/cero@latest"
  "github.com/gwen001/github-subdomains@latest"
  "github.com/haccer/subjack@latest"
  "github.com/praetorian-inc/fingerprintx/cmd/fingerprintx@latest"
)

for tool in "${GO_TOOLS[@]}"; do
  binary=$(basename "$tool" | cut -d'@' -f1)
  case "$tool" in
    github.com/ffuf/ffuf/v2@*) binary="ffuf" ;;
  esac
  if command -v "$binary" &>/dev/null; then
    echo -e "${GREEN}  -> ${binary} is already installed; skipping.${NC}"
    continue
  fi
  echo -e "${BLUE}  -> Installing ${binary}...${NC}"
  go install -v "$tool" 2>&1 | tail -n 1
done

# ------------------------------------------------------------------------------
# STEP 4: Python-Based Recon & Parameter Mining Tools
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Step 4/8] Installing Python security auditing tools...${NC}"

# Use one project-local virtual environment. This avoids Kali/Debian's PEP 668
# restriction while keeping Python packages isolated from the system interpreter.
PYTHON_VENV="$SCRIPT_DIR/.venv"
if [ ! -x "$PYTHON_VENV/bin/python" ]; then
  echo -e "${BLUE}  -> Creating Python virtual environment at ${PYTHON_VENV}...${NC}"
  python3 -m venv "$PYTHON_VENV"
fi
export PATH="$PYTHON_VENV/bin:$PATH"
"$PYTHON_VENV/bin/python" -m pip install --upgrade pip

PYTHON_TOOLS=(
  "arjun"
  "wafw00f"
  "waymore"
  "dnsvalidator"
  "knockpy"
)

for ptool in "${PYTHON_TOOLS[@]}"; do
  if command -v "$ptool" &>/dev/null; then
    echo -e "${GREEN}  -> ${ptool} is already installed; skipping.${NC}"
    continue
  fi
  echo -e "${BLUE}  -> Installing ${ptool} in project virtual environment...${NC}"
  case "$ptool" in
    dnsvalidator)
      "$PYTHON_VENV/bin/python" -m pip install \
        "git+https://github.com/vortexau/dnsvalidator.git"
      ;;
    knockpy)
      # The `knockpy` PyPI name belongs to an unrelated statistics package.
      "$PYTHON_VENV/bin/python" -m pip install \
        "git+https://github.com/guelfoweb/KnockPy.git"
      ;;
    *)
      "$PYTHON_VENV/bin/python" -m pip install "$ptool"
      ;;
  esac
done

# ParamSpider installation (clone if not packaged)
if ! command -v paramspider &>/dev/null; then
  echo -e "${BLUE}  -> Installing ParamSpider from source...${NC}"
  PARAMSPIDER_DIR="$SCRIPT_DIR/.tools/ParamSpider"
  if [ -e "$PARAMSPIDER_DIR" ] && [ ! -d "$PARAMSPIDER_DIR/.git" ]; then
    echo -e "${RED}[!] $PARAMSPIDER_DIR exists but is not a valid Git checkout.${NC}" >&2
    echo -e "${YELLOW}    Move that directory aside, then rerun setup.sh.${NC}" >&2
    exit 1
  fi
  if [ ! -d "$PARAMSPIDER_DIR/.git" ]; then
    mkdir -p "$SCRIPT_DIR/.tools"
    git clone https://github.com/devanshbatham/ParamSpider.git "$PARAMSPIDER_DIR"
  fi
  "$PYTHON_VENV/bin/python" -m pip install "$PARAMSPIDER_DIR"
fi

# JS Beautify (Python package exposes the js-beautify CLI)
if ! command -v js-beautify &>/dev/null; then
  echo -e "${BLUE}  -> Installing js-beautify in project virtual environment...${NC}"
  "$PYTHON_VENV/bin/python" -m pip install jsbeautifier
fi

# ------------------------------------------------------------------------------
# STEP 5: TruffleHog, Gitleaks & MassDNS (Native Binaries)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Step 5/8] Installing TruffleHog, Gitleaks, and compiling MassDNS...${NC}"

# 1. TruffleHog (Official binary)
if ! command -v trufflehog &>/dev/null; then
  echo -e "${BLUE}  -> Installing TruffleHog...${NC}"
  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin
fi

# 2. Gitleaks
if ! command -v gitleaks &>/dev/null; then
  echo -e "${BLUE}  -> Installing Gitleaks...${NC}"
  GITLEAKS_VER="8.18.2"
  wget -q "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VER}/gitleaks_${GITLEAKS_VER}_linux_x64.tar.gz" -O /tmp/gitleaks.tar.gz
  tar -xzf /tmp/gitleaks.tar.gz -C /tmp/
  sudo mv /tmp/gitleaks /usr/local/bin/
  rm -f /tmp/gitleaks.tar.gz
fi

# 3. MassDNS compilation (required for shuffledns and active brute-forcing)
if ! command -v massdns &>/dev/null; then
  echo -e "${BLUE}  -> Compiling MassDNS from source...${NC}"
  mkdir -p "$HOME/tools"
  if [ ! -d "$HOME/tools/massdns" ]; then
    git clone https://github.com/blechschmidt/massdns.git "$HOME/tools/massdns"
  fi
  make -C "$HOME/tools/massdns" -j$(nproc)
  sudo cp "$HOME/tools/massdns/bin/massdns" /usr/local/bin/
fi

# ------------------------------------------------------------------------------
# STEP 6: Nuclei Templates & Resolver Pool Initialization
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Step 6/8] Updating Nuclei templates & generating trusted resolvers...${NC}"

# Update Nuclei templates
if command -v nuclei &>/dev/null; then
  nuclei -update-templates -silent || true
fi

# Generate trusted DNS resolvers pool if not present
mkdir -p "$HOME/.config"
RESOLVERS_FILE="$HOME/resolvers.txt"
if [ ! -f "$RESOLVERS_FILE" ] || [ ! -s "$RESOLVERS_FILE" ]; then
  echo -e "${BLUE}  -> Generating verified resolver list via dnsvalidator (this may take 1-2 min)...${NC}"
  dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 50 -o "$RESOLVERS_FILE" 2>/dev/null || {
    echo -e "${YELLOW}[!] dnsvalidator timeout. Writing standard reliable public resolvers...${NC}"
    cat << 'EOF' > "$RESOLVERS_FILE"
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
EOF
  }
fi
# Public lists can temporarily yield very few usable servers. Always retain a
# small trusted baseline so shuffledns/dnsx have a viable resolver pool.
if [ "$(wc -l < "$RESOLVERS_FILE")" -lt 5 ]; then
  cat << 'EOF' >> "$RESOLVERS_FILE"
1.1.1.1
1.0.0.1
8.8.8.8
8.8.4.4
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
EOF
  sort -u -o "$RESOLVERS_FILE" "$RESOLVERS_FILE"
fi
echo -e "${GREEN}[+] Public resolvers configured at: $RESOLVERS_FILE ($(wc -l < "$RESOLVERS_FILE") resolvers)${NC}"

# ------------------------------------------------------------------------------
# STEP 7: Wordlist Directory Setup
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Step 7/8] Verifying SecLists and local wordlists...${NC}"

SECLISTS_DIR="/usr/share/wordlists/SecLists"
if [ ! -d "$SECLISTS_DIR" ]; then
  echo -e "${BLUE}  -> Installing SecLists to /usr/share/wordlists/SecLists...${NC}"
  sudo mkdir -p /usr/share/wordlists
  if command -v seclists &>/dev/null; then
    sudo apt-get install -y seclists 2>/dev/null || true
  else
    sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR" 2>/dev/null || true
  fi
fi

# ------------------------------------------------------------------------------
# STEP 8: Tool Verification Health-Check
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[Step 8/8] Running tool verification health-check...${NC}"

REQUIRED_TOOLS=(
  "subfinder"
  "httpx"
  "dnsx"
  "naabu"
  "katana"
  "nuclei"
  "shuffledns"
  "massdns"
  "ffuf"
  "waybackurls"
  "gau"
  "waymore"
  "hakrawler"
  "gospider"
  "trufflehog"
  "gitleaks"
  "cero"
  "subjack"
  "gowitness"
  "fingerprintx"
  "interactsh-client"
  "alterx"
  "dnsvalidator"
  "paramspider"
  "js-beautify"
  "knockpy"
  "arjun"
  "wafw00f"
  "nmap"
  "masscan"
  "jq"
  "curl"
)

echo -e "\n${BOLD}Tool Status Matrix:${NC}"
printf "%-25s %-12s %-30s\n" "TOOL" "STATUS" "PATH"
echo "--------------------------------------------------------------------"

MISSING_COUNT=0
for t in "${REQUIRED_TOOLS[@]}"; do
  if command -v "$t" &>/dev/null; then
    printf "%-25s ${GREEN}%-12s${NC} %-30s\n" "$t" "INSTALLED" "$(which "$t")"
  else
    printf "%-25s ${RED}%-12s${NC} %-30s\n" "$t" "MISSING" "Not found in PATH"
    MISSING_COUNT=$((MISSING_COUNT + 1))
  fi
done

echo "--------------------------------------------------------------------"

if [ $MISSING_COUNT -eq 0 ]; then
  echo -e "\n${GREEN}${BOLD}[SUCCESS] All $(echo ${#REQUIRED_TOOLS[@]}) core reconnaissance and security auditing tools are installed and ready!${NC}"
else
  echo -e "\n${YELLOW}[!] $MISSING_COUNT tool(s) were not found in PATH. Ensure '$HOME/go/bin' and '$HOME/.local/bin' are in your PATH.${NC}"
fi

echo -e "\n${CYAN}Add the following line to your ~/.bashrc or ~/.zshrc if not already present:${NC}"
echo -e "${BOLD}export PATH=\"\$PATH:/usr/local/go/bin:\$HOME/go/bin:\$HOME/.local/bin\"${NC}\n"
echo -e "${CYAN}Activate project Python tools with:${NC} ${BOLD}source \"$PYTHON_VENV/bin/activate\"${NC}\n"
