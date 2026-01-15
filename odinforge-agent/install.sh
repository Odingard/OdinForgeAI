#!/bin/bash
set -e

# OdinForge Agent Installer for Linux
# Usage: curl -sSL https://YOUR_SERVER/api/agents/install.sh | sudo bash -s -- --server-url https://YOUR_SERVER --registration-token YOUR_TOKEN
# Or with env vars: curl -sSL https://YOUR_SERVER/api/agents/install.sh | SERVER_URL=https://YOUR_SERVER TOKEN=YOUR_TOKEN sudo -E bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}OdinForge Agent Installer${NC}"
echo "================================"
echo ""

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --server-url)
            CLI_SERVER_URL="$2"
            shift 2
            ;;
        --registration-token)
            CLI_TOKEN="$2"
            shift 2
            ;;
        --token)
            CLI_TOKEN="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --server-url URL              OdinForge server URL"
            echo "  --registration-token TOKEN   Registration token for auto-registration"
            echo "  --token TOKEN                Alias for --registration-token"
            echo "  -h, --help                   Show this help message"
            exit 0
            ;;
        *)
            shift
            ;;
    esac
done

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Check for Linux
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "linux" ]; then
    echo -e "${RED}Error: This script is for Linux only. Use install.ps1 for Windows.${NC}"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

BINARY_NAME="odinforge-agent-linux-${ARCH}"
echo -e "Detected platform: ${GREEN}linux-${ARCH}${NC}"

# Default server URL - automatically embedded when downloaded from server
DEFAULT_SERVER_URL="__SERVER_URL_PLACEHOLDER__"

# Check if URL was embedded (starts with http)
url_is_embedded() {
    case "$1" in
        http://*|https://*) return 0 ;;
        *) return 1 ;;
    esac
}

# Get server URL from CLI args, environment, default, or prompt (in priority order)
if [ -n "$CLI_SERVER_URL" ]; then
    SERVER_URL="$CLI_SERVER_URL"
elif [ -n "$ODINFORGE_SERVER_URL" ]; then
    SERVER_URL="$ODINFORGE_SERVER_URL"
elif [ -n "$SERVER_URL" ]; then
    SERVER_URL="$SERVER_URL"
elif url_is_embedded "$DEFAULT_SERVER_URL"; then
    SERVER_URL="$DEFAULT_SERVER_URL"
    echo -e "${GREEN}Using server: ${SERVER_URL}${NC}"
else
    echo -e "${YELLOW}Enter OdinForge server URL:${NC}"
    read -r SERVER_URL < /dev/tty
fi

# Remove trailing slash
SERVER_URL="${SERVER_URL%/}"

# Default registration token - can be embedded when downloaded with ?token=<value>
DEFAULT_TOKEN="__REGISTRATION_TOKEN_PLACEHOLDER__"

# Check if token was embedded (doesn't contain placeholder text)
token_is_embedded() {
    case "$1" in
        *__REGISTRATION_TOKEN_PLACEHOLDER__*) return 1 ;;
        "") return 1 ;;
        *) return 0 ;;
    esac
}

# Get registration token from CLI args, environment, embedded default, or prompt (in priority order)
if [ -n "$CLI_TOKEN" ]; then
    TOKEN="$CLI_TOKEN"
elif [ -n "$ODINFORGE_TOKEN" ]; then
    TOKEN="$ODINFORGE_TOKEN"
elif [ -n "$TOKEN" ]; then
    TOKEN="$TOKEN"
elif token_is_embedded "$DEFAULT_TOKEN"; then
    TOKEN="$DEFAULT_TOKEN"
    echo -e "${GREEN}Using embedded registration token${NC}"
else
    echo -e "${YELLOW}Enter registration token:${NC}"
    read -r TOKEN < /dev/tty
fi

# Download the agent binary
echo "Downloading agent binary..."
DOWNLOAD_URL="${SERVER_URL}/agents/${BINARY_NAME}"
curl -sSL -o /tmp/odinforge-agent "$DOWNLOAD_URL" || {
    echo -e "${RED}Error: Failed to download agent from ${DOWNLOAD_URL}${NC}"
    exit 1
}

# Install the binary
echo "Installing agent..."
chmod +x /tmp/odinforge-agent
mv /tmp/odinforge-agent /usr/local/bin/odinforge-agent

# Create configuration and data directories
mkdir -p /etc/odinforge
mkdir -p /var/lib/odinforge-agent

# Store credentials in a secure environment file (readable only by root)
cat > /etc/odinforge/agent.env << EOF
ODINFORGE_SERVER_URL=${SERVER_URL}
ODINFORGE_REGISTRATION_TOKEN=${TOKEN}
ODINFORGE_TENANT_ID=default
EOF
chmod 600 /etc/odinforge/agent.env

# Stop existing service if running
echo "Checking for existing service..."
systemctl stop odinforge-agent 2>/dev/null || true

# Install systemd service
echo "Installing systemd service..."
cat > /etc/systemd/system/odinforge-agent.service << EOF
[Unit]
Description=OdinForge Security Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/odinforge-agent
EnvironmentFile=/etc/odinforge/agent.env
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

# Reload and start service
systemctl daemon-reload
systemctl enable odinforge-agent
systemctl start odinforge-agent

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Agent installed and started successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Check status: systemctl status odinforge-agent"
echo "View logs: journalctl -u odinforge-agent -f"
echo "Stop service: systemctl stop odinforge-agent"
echo "Start service: systemctl start odinforge-agent"
echo ""
echo -e "${GREEN}Installation complete!${NC}"
