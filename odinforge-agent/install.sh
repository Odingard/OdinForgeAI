#!/bin/bash
set -e

# OdinForge Agent Installer for Linux
# Usage: curl -sSL https://YOUR_SERVER/api/agents/install.sh | sudo bash
# Or with args: curl -sSL https://YOUR_SERVER/api/agents/install.sh | sudo bash -s -- --server-url https://YOUR_SERVER --api-key YOUR_KEY

VERSION="1.0.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values - automatically embedded when downloaded from server
DEFAULT_SERVER_URL="__SERVER_URL_PLACEHOLDER__"
DEFAULT_API_KEY="__API_KEY_PLACEHOLDER__"
DEFAULT_TENANT_ID="default"

# Runtime options
DRY_RUN=false
FORCE=false
COMMAND="install"

print_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║           OdinForge Agent Installer v${VERSION}              ║"
    echo "║           Adversarial Exposure Validation                 ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_help() {
    echo "OdinForge Agent Installer for Linux"
    echo ""
    echo "Usage: install.sh [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  install     Install the OdinForge agent (default)"
    echo "  uninstall   Remove the OdinForge agent"
    echo "  status      Check agent status"
    echo ""
    echo "Options:"
    echo "  --server-url URL    OdinForge server URL (required for install)"
    echo "  --api-key KEY       API key for agent authentication"
    echo "  --tenant-id ID      Tenant ID (default: 'default')"
    echo "  --dry-run           Show what would be done without making changes"
    echo "  --force             Force reinstall even if already installed"
    echo "  -h, --help          Show this help message"
    echo "  -v, --version       Show version"
    echo ""
    echo "Environment Variables:"
    echo "  ODINFORGE_SERVER_URL    Server URL"
    echo "  ODINFORGE_API_KEY       API key"
    echo "  ODINFORGE_TENANT_ID     Tenant ID"
    echo ""
    echo "Examples:"
    echo "  # Install with embedded credentials (from server-generated command)"
    echo "  curl -sSL 'https://server/api/agents/install.sh?token=abc' | sudo bash"
    echo ""
    echo "  # Install with explicit arguments"
    echo "  sudo ./install.sh --server-url https://odinforge.example.com --api-key mykey"
    echo ""
    echo "  # Check status"
    echo "  sudo ./install.sh status"
    echo ""
    echo "  # Uninstall"
    echo "  sudo ./install.sh uninstall"
}

# Parse command-line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            install|uninstall|status)
                COMMAND="$1"
                shift
                ;;
            --server-url)
                CLI_SERVER_URL="$2"
                shift 2
                ;;
            --api-key)
                CLI_API_KEY="$2"
                shift 2
                ;;
            --registration-token|--token)
                CLI_API_KEY="$2"
                shift 2
                ;;
            --tenant-id)
                CLI_TENANT_ID="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            -h|--help)
                print_help
                exit 0
                ;;
            -v|--version)
                echo "OdinForge Agent Installer v${VERSION}"
                exit 0
                ;;
            *)
                shift
                ;;
        esac
    done
}

# Check if value is a placeholder
is_placeholder() {
    case "$1" in
        *__*PLACEHOLDER__*|"") return 0 ;;
        *) return 1 ;;
    esac
}

# Check if value starts with http
is_url() {
    case "$1" in
        http://*|https://*) return 0 ;;
        *) return 1 ;;
    esac
}

# Resolve configuration values
resolve_config() {
    # Server URL: CLI > ENV > Embedded > Prompt
    if [ -n "$CLI_SERVER_URL" ]; then
        SERVER_URL="$CLI_SERVER_URL"
    elif [ -n "$ODINFORGE_SERVER_URL" ]; then
        SERVER_URL="$ODINFORGE_SERVER_URL"
    elif ! is_placeholder "$DEFAULT_SERVER_URL" && is_url "$DEFAULT_SERVER_URL"; then
        SERVER_URL="$DEFAULT_SERVER_URL"
    else
        echo -e "${RED}Error: Server URL is required.${NC}"
        echo "Use --server-url or set ODINFORGE_SERVER_URL environment variable."
        exit 1
    fi
    SERVER_URL="${SERVER_URL%/}"

    # API Key: CLI > ENV > Embedded > Error
    if [ -n "$CLI_API_KEY" ]; then
        API_KEY="$CLI_API_KEY"
    elif [ -n "$ODINFORGE_API_KEY" ]; then
        API_KEY="$ODINFORGE_API_KEY"
    elif [ -n "$ODINFORGE_TOKEN" ]; then
        API_KEY="$ODINFORGE_TOKEN"
    elif ! is_placeholder "$DEFAULT_API_KEY"; then
        API_KEY="$DEFAULT_API_KEY"
    else
        echo -e "${RED}Error: API key is required.${NC}"
        echo "Use --api-key or set ODINFORGE_API_KEY environment variable."
        exit 1
    fi

    # Tenant ID: CLI > ENV > Embedded > Default
    if [ -n "$CLI_TENANT_ID" ]; then
        TENANT_ID="$CLI_TENANT_ID"
    elif [ -n "$ODINFORGE_TENANT_ID" ]; then
        TENANT_ID="$ODINFORGE_TENANT_ID"
    elif [ -n "$DEFAULT_TENANT_ID" ] && [ "$DEFAULT_TENANT_ID" != "__TENANT_ID_PLACEHOLDER__" ]; then
        TENANT_ID="$DEFAULT_TENANT_ID"
    else
        TENANT_ID="default"
    fi
}

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    if [ "$OS" != "linux" ]; then
        echo -e "${RED}Error: This script is for Linux only. Use install.ps1 for Windows.${NC}"
        exit 1
    fi

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        *)
            echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}"
            exit 1
            ;;
    esac

    BINARY_NAME="odinforge-agent-linux-${ARCH}"
    echo -e "Platform: ${GREEN}linux-${ARCH}${NC}"
}

# Check for root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
        exit 1
    fi
}

# Check if agent is already installed
is_installed() {
    [ -f /usr/local/bin/odinforge-agent ]
}

# Install the agent
do_install() {
    echo -e "\n${BLUE}Installing OdinForge Agent...${NC}"
    
    resolve_config
    detect_platform

    if is_installed && [ "$FORCE" != "true" ]; then
        echo -e "${YELLOW}Agent is already installed. Use --force to reinstall.${NC}"
        exit 0
    fi

    echo -e "Server: ${GREEN}${SERVER_URL}${NC}"
    echo -e "Tenant: ${GREEN}${TENANT_ID}${NC}"
    echo ""

    if [ "$DRY_RUN" = "true" ]; then
        echo -e "${YELLOW}[DRY RUN] Would perform the following actions:${NC}"
        echo "  - Download agent binary from ${SERVER_URL}/agents/${BINARY_NAME}"
        echo "  - Install binary to /usr/local/bin/odinforge-agent"
        echo "  - Create config directory /etc/odinforge"
        echo "  - Create data directory /var/lib/odinforge-agent"
        echo "  - Install systemd service"
        echo "  - Start agent service"
        exit 0
    fi

    # Download agent binary
    echo "Downloading agent binary..."
    DOWNLOAD_URL="${SERVER_URL}/agents/${BINARY_NAME}"
    if ! curl -sSL -f -o /tmp/odinforge-agent "$DOWNLOAD_URL"; then
        echo -e "${RED}Error: Failed to download agent from ${DOWNLOAD_URL}${NC}"
        exit 1
    fi

    # Stop existing service if running
    systemctl stop odinforge-agent 2>/dev/null || true

    # Install binary
    echo "Installing binary..."
    chmod +x /tmp/odinforge-agent
    mv /tmp/odinforge-agent /usr/local/bin/odinforge-agent

    # Create directories
    mkdir -p /etc/odinforge
    mkdir -p /var/lib/odinforge-agent

    # Write config file
    echo "Writing configuration..."
    cat > /etc/odinforge/agent.env << EOF
ODINFORGE_SERVER_URL=${SERVER_URL}
ODINFORGE_API_KEY=${API_KEY}
ODINFORGE_TENANT_ID=${TENANT_ID}
EOF
    chmod 600 /etc/odinforge/agent.env

    # Install systemd service
    echo "Installing systemd service..."
    cat > /etc/systemd/system/odinforge-agent.service << EOF
[Unit]
Description=OdinForge Security Agent
Documentation=https://github.com/odinforge/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/odinforge-agent
EnvironmentFile=/etc/odinforge/agent.env
Restart=always
RestartSec=10
User=root
WorkingDirectory=/var/lib/odinforge-agent

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/odinforge-agent
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

    # Start service
    echo "Starting service..."
    systemctl daemon-reload
    systemctl enable odinforge-agent
    systemctl start odinforge-agent

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         Agent installed and started successfully!         ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Quick commands:"
    echo "  Status:    sudo odinforge-agent status   OR   systemctl status odinforge-agent"
    echo "  Logs:      journalctl -u odinforge-agent -f"
    echo "  Restart:   systemctl restart odinforge-agent"
    echo "  Uninstall: curl -sSL '${SERVER_URL}/api/agents/install.sh' | sudo bash -s -- uninstall"
}

# Uninstall the agent
do_uninstall() {
    echo -e "\n${BLUE}Uninstalling OdinForge Agent...${NC}"

    if [ "$DRY_RUN" = "true" ]; then
        echo -e "${YELLOW}[DRY RUN] Would perform the following actions:${NC}"
        echo "  - Stop and disable odinforge-agent service"
        echo "  - Remove /usr/local/bin/odinforge-agent"
        echo "  - Remove /etc/odinforge/"
        echo "  - Remove /var/lib/odinforge-agent/"
        echo "  - Remove /etc/systemd/system/odinforge-agent.service"
        exit 0
    fi

    # Stop and disable service
    echo "Stopping service..."
    systemctl stop odinforge-agent 2>/dev/null || true
    systemctl disable odinforge-agent 2>/dev/null || true

    # Remove files
    echo "Removing files..."
    rm -f /usr/local/bin/odinforge-agent
    rm -f /etc/systemd/system/odinforge-agent.service
    rm -rf /etc/odinforge
    rm -rf /var/lib/odinforge-agent

    # Reload systemd
    systemctl daemon-reload

    echo ""
    echo -e "${GREEN}Agent uninstalled successfully.${NC}"
}

# Show agent status
do_status() {
    echo -e "\n${BLUE}OdinForge Agent Status${NC}"
    echo "========================"
    echo ""

    if ! is_installed; then
        echo -e "Binary: ${RED}Not installed${NC}"
        exit 1
    fi

    echo -e "Binary: ${GREEN}Installed${NC} (/usr/local/bin/odinforge-agent)"
    
    if [ -f /etc/odinforge/agent.env ]; then
        echo -e "Config: ${GREEN}Present${NC} (/etc/odinforge/agent.env)"
        
        # Show non-sensitive config
        source /etc/odinforge/agent.env 2>/dev/null || true
        if [ -n "$ODINFORGE_SERVER_URL" ]; then
            echo -e "Server: ${GREEN}${ODINFORGE_SERVER_URL}${NC}"
        fi
        if [ -n "$ODINFORGE_TENANT_ID" ]; then
            echo -e "Tenant: ${GREEN}${ODINFORGE_TENANT_ID}${NC}"
        fi
    else
        echo -e "Config: ${YELLOW}Missing${NC}"
    fi

    echo ""
    
    if systemctl is-active --quiet odinforge-agent 2>/dev/null; then
        echo -e "Service: ${GREEN}Running${NC}"
        echo ""
        echo "Recent logs:"
        journalctl -u odinforge-agent -n 5 --no-pager 2>/dev/null || true
    elif systemctl is-enabled --quiet odinforge-agent 2>/dev/null; then
        echo -e "Service: ${YELLOW}Enabled but not running${NC}"
    else
        echo -e "Service: ${RED}Not configured${NC}"
    fi
}

# Main entry point
main() {
    parse_args "$@"

    case "$COMMAND" in
        install)
            print_banner
            check_root
            do_install
            ;;
        uninstall)
            print_banner
            check_root
            do_uninstall
            ;;
        status)
            check_root
            do_status
            ;;
        *)
            print_help
            exit 1
            ;;
    esac
}

main "$@"
