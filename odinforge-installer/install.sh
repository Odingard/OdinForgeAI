#!/bin/bash
#
# OdinForge Agent Installer Script
# Usage: curl -fsSL https://your-server/api/install.sh | sudo bash -s -- --server-url URL --registration-token TOKEN
#
# NOTE: This script downloads from GitHub releases. SHA256 verification is not
# performed in this script version. For checksum verification, use the standalone
# CLI installer with --skip-checksum=false (default).
#

set -e

VERSION="1.0.2"
GITHUB_BASE_URL="https://github.com/Odingard/OdinForgeAI/releases/download/agent-v${VERSION}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

banner() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}        OdinForge Agent Installer v${VERSION}                    ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}     Adversarial Exposure Validation Platform            ${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

usage() {
    cat << EOF
Usage: $0 [options]

Required Options:
  --server-url <url>            OdinForge server URL
  --registration-token <token>  Registration token for auto-registration

Optional:
  --platform <platform>         Override platform detection
  --output <path>               Download destination (default: /tmp)
  --help, -h                    Show this help message

Platforms: linux-amd64, linux-arm64, darwin-amd64, darwin-arm64

Examples:
  curl -fsSL https://server/api/install.sh | sudo bash -s -- \\
    --server-url https://odinforge.example.com \\
    --registration-token abc123
EOF
}

# Parse arguments
SERVER_URL=""
REGISTRATION_TOKEN=""
PLATFORM=""
OUTPUT_DIR="/tmp"

while [[ $# -gt 0 ]]; do
    case $1 in
        --server-url)
            SERVER_URL="$2"
            shift 2
            ;;
        --registration-token)
            REGISTRATION_TOKEN="$2"
            shift 2
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help|-h)
            banner
            usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

detect_platform() {
    local os arch
    
    case "$(uname -s)" in
        Linux*)  os="linux" ;;
        Darwin*) os="darwin" ;;
        *)       log_error "Unsupported OS: $(uname -s)"; exit 1 ;;
    esac
    
    case "$(uname -m)" in
        x86_64|amd64) arch="amd64" ;;
        arm64|aarch64) arch="arm64" ;;
        *)             log_error "Unsupported architecture: $(uname -m)"; exit 1 ;;
    esac
    
    echo "${os}-${arch}"
}

get_download_url() {
    local platform="$1"
    case "$platform" in
        linux-amd64)  echo "${GITHUB_BASE_URL}/odinforge-agent-linux-amd64" ;;
        linux-arm64)  echo "${GITHUB_BASE_URL}/odinforge-agent-linux-arm64" ;;
        darwin-amd64) echo "${GITHUB_BASE_URL}/odinforge-agent-darwin-amd64" ;;
        darwin-arm64) echo "${GITHUB_BASE_URL}/odinforge-agent-darwin-arm64" ;;
        *)            log_error "Unknown platform: $platform"; exit 1 ;;
    esac
}

get_filename() {
    local platform="$1"
    case "$platform" in
        linux-amd64)  echo "odinforge-agent-linux-amd64" ;;
        linux-arm64)  echo "odinforge-agent-linux-arm64" ;;
        darwin-amd64) echo "odinforge-agent-darwin-amd64" ;;
        darwin-arm64) echo "odinforge-agent-darwin-arm64" ;;
        *)            echo "odinforge-agent" ;;
    esac
}

main() {
    banner
    
    # Validate required args
    if [[ -z "$SERVER_URL" ]]; then
        log_error "Missing required option: --server-url"
        usage
        exit 1
    fi
    
    if [[ -z "$REGISTRATION_TOKEN" ]]; then
        log_error "Missing required option: --registration-token"
        usage
        exit 1
    fi
    
    # Detect or use provided platform
    if [[ -z "$PLATFORM" ]]; then
        PLATFORM=$(detect_platform)
        log_success "Detected platform: $PLATFORM"
    else
        log_info "Using specified platform: $PLATFORM"
    fi
    
    # Get download URL and filename
    DOWNLOAD_URL=$(get_download_url "$PLATFORM")
    FILENAME=$(get_filename "$PLATFORM")
    DEST_PATH="${OUTPUT_DIR}/${FILENAME}"
    
    log_info "Agent version: v${VERSION}"
    log_info "Server URL: ${SERVER_URL}"
    log_info "Downloading from: ${DOWNLOAD_URL}"
    
    # Download
    log_info "Downloading agent..."
    if command -v curl &> /dev/null; then
        curl -fsSL -o "$DEST_PATH" "$DOWNLOAD_URL"
    elif command -v wget &> /dev/null; then
        wget -q -O "$DEST_PATH" "$DOWNLOAD_URL"
    else
        log_error "Neither curl nor wget found. Please install one."
        exit 1
    fi
    log_success "Download complete: $DEST_PATH"
    
    # Make executable
    chmod +x "$DEST_PATH"
    log_success "Made executable"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        log_warn "Not running as root. Installation may fail."
        log_info "Re-run with sudo for proper installation."
    fi
    
    # Run install
    log_info "Running agent installer..."
    "$DEST_PATH" install \
        --server-url "$SERVER_URL" \
        --registration-token "$REGISTRATION_TOKEN"
    
    log_success "Agent installed successfully!"
    log_info "Agent binary: $DEST_PATH"
    log_info "Server: $SERVER_URL"
}

main
