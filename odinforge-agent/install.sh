#!/bin/bash
set -e

# OdinForge Agent Installer
# Usage: curl -sSL https://YOUR_SERVER/api/agents/install.sh | sudo bash
# Or with env vars: curl -sSL https://YOUR_SERVER/api/agents/install.sh | SERVER_URL=https://YOUR_SERVER TOKEN=YOUR_TOKEN sudo -E bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}OdinForge Agent Installer${NC}"
echo "================================"

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
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

case "$OS" in
    linux)
        PLATFORM="linux"
        ;;
    darwin)
        PLATFORM="darwin"
        ;;
    *)
        echo -e "${RED}Error: Unsupported OS: $OS${NC}"
        exit 1
        ;;
esac

BINARY_NAME="odinforge-agent-${PLATFORM}-${ARCH}"
echo -e "Detected platform: ${GREEN}${PLATFORM}-${ARCH}${NC}"

# Get server URL from environment or prompt
if [ -z "$ODINFORGE_SERVER_URL" ] && [ -z "$SERVER_URL" ]; then
    echo -e "${YELLOW}Enter OdinForge server URL:${NC}"
    read -r SERVER_URL < /dev/tty
else
    SERVER_URL="${ODINFORGE_SERVER_URL:-$SERVER_URL}"
fi

# Remove trailing slash
SERVER_URL="${SERVER_URL%/}"

# Get registration token from environment or prompt
if [ -z "$ODINFORGE_TOKEN" ] && [ -z "$TOKEN" ]; then
    echo -e "${YELLOW}Enter registration token:${NC}"
    read -r TOKEN < /dev/tty
else
    TOKEN="${ODINFORGE_TOKEN:-$TOKEN}"
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

# Create configuration directory
mkdir -p /etc/odinforge

# Store the API key
echo -n "$TOKEN" > /etc/odinforge/api_key
chmod 600 /etc/odinforge/api_key

# Platform-specific service installation
if [ "$PLATFORM" = "linux" ]; then
    echo "Installing systemd service..."
    
    cat > /etc/systemd/system/odinforge-agent.service << EOF
[Unit]
Description=OdinForge Security Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/odinforge-agent
Environment=ODINFORGE_SERVER_URL=${SERVER_URL}
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable odinforge-agent
    systemctl start odinforge-agent
    
    echo -e "${GREEN}Agent installed and started successfully!${NC}"
    echo "Check status: systemctl status odinforge-agent"
    echo "View logs: journalctl -u odinforge-agent -f"

elif [ "$PLATFORM" = "darwin" ]; then
    echo "Installing launchd service..."
    
    cat > /Library/LaunchDaemons/com.odinforge.agent.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.odinforge.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/odinforge-agent</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>ODINFORGE_SERVER_URL</key>
        <string>${SERVER_URL}</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/odinforge-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/odinforge-agent.error.log</string>
</dict>
</plist>
EOF

    launchctl bootstrap system /Library/LaunchDaemons/com.odinforge.agent.plist 2>/dev/null || \
    launchctl load /Library/LaunchDaemons/com.odinforge.agent.plist 2>/dev/null || true
    
    echo -e "${GREEN}Agent installed and started successfully!${NC}"
    echo "Check status: sudo launchctl print system/com.odinforge.agent"
    echo "View logs: tail -f /var/log/odinforge-agent.log"
fi

echo ""
echo -e "${GREEN}Installation complete!${NC}"
