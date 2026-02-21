#!/bin/bash
set -e

# OdinForge Agent Installer for Linux
# Usage: curl -sSL https://YOUR_SERVER/api/agents/install.sh | sudo bash
# Or with args: curl -sSL https://YOUR_SERVER/api/agents/install.sh | sudo bash -s -- --server-url https://YOUR_SERVER --api-key YOUR_KEY

VERSION="1.1.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default values - automatically embedded when downloaded from server
DEFAULT_SERVER_URL="__SERVER_URL_PLACEHOLDER__"
DEFAULT_API_KEY="__API_KEY_PLACEHOLDER__"
DEFAULT_REGISTRATION_TOKEN="__REGISTRATION_TOKEN_PLACEHOLDER__"
DEFAULT_TENANT_ID="default"

# Runtime options
DRY_RUN=false
FORCE=false
COMMAND="install"

# Installation paths
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/odinforge"
DATA_DIR="/var/lib/odinforge-agent"
LOG_DIR="/var/log/odinforge"
SERVICE_NAME="odinforge-agent"
SERVICE_USER="odinforge"

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
                CLI_REGISTRATION_TOKEN="$2"
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

    # API Key or Registration Token: CLI > ENV > Embedded > Error
    # Registration tokens allow the agent to auto-register and obtain its own API key
    if [ -n "$CLI_API_KEY" ]; then
        API_KEY="$CLI_API_KEY"
        AUTH_MODE="api_key"
    elif [ -n "$CLI_REGISTRATION_TOKEN" ]; then
        REGISTRATION_TOKEN="$CLI_REGISTRATION_TOKEN"
        AUTH_MODE="registration_token"
    elif [ -n "$ODINFORGE_API_KEY" ]; then
        API_KEY="$ODINFORGE_API_KEY"
        AUTH_MODE="api_key"
    elif [ -n "$ODINFORGE_TOKEN" ]; then
        REGISTRATION_TOKEN="$ODINFORGE_TOKEN"
        AUTH_MODE="registration_token"
    elif ! is_placeholder "$DEFAULT_REGISTRATION_TOKEN"; then
        REGISTRATION_TOKEN="$DEFAULT_REGISTRATION_TOKEN"
        AUTH_MODE="registration_token"
    elif ! is_placeholder "$DEFAULT_API_KEY"; then
        API_KEY="$DEFAULT_API_KEY"
        AUTH_MODE="api_key"
    else
        echo -e "${RED}Error: API key or registration token is required.${NC}"
        echo "Use --api-key, --registration-token, or set ODINFORGE_API_KEY environment variable."
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
        armv7l|armv7) ARCH="arm64" ;;
        *)
            echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}"
            echo "Supported: x86_64/amd64, aarch64/arm64, armv7l"
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

# Pre-flight validation
preflight_checks() {
    echo -e "\n${BLUE}Running pre-flight checks...${NC}"
    local failed=0

    # Check disk space (need at least 100MB)
    local available_mb
    available_mb=$(df -m /usr/local/bin 2>/dev/null | tail -1 | awk '{print $4}')
    if [ -n "$available_mb" ] && [ "$available_mb" -lt 100 ]; then
        echo -e "  ${RED}[FAIL]${NC} Insufficient disk space: ${available_mb}MB available (need 100MB)"
        failed=1
    else
        echo -e "  ${GREEN}[OK]${NC} Disk space: ${available_mb:-unknown}MB available"
    fi

    # Check required commands
    for cmd in curl chmod mkdir; do
        if command -v "$cmd" &>/dev/null; then
            echo -e "  ${GREEN}[OK]${NC} Command: $cmd"
        else
            echo -e "  ${RED}[FAIL]${NC} Required command not found: $cmd"
            failed=1
        fi
    done

    # Check init system availability
    local init_sys
    init_sys=$(detect_init_system)
    if [ "$init_sys" = "none" ]; then
        echo -e "  ${YELLOW}[WARN]${NC} No supported init system found (will run manually)"
    else
        echo -e "  ${GREEN}[OK]${NC} Init system: $init_sys"
    fi

    # Check network connectivity to server
    local health_url="${SERVER_URL}/healthz"
    if curl -sSL -f -H "ngrok-skip-browser-warning: true" --connect-timeout 10 -o /dev/null "$health_url" 2>/dev/null; then
        echo -e "  ${GREEN}[OK]${NC} Server reachable: ${SERVER_URL}"
    else
        echo -e "  ${RED}[FAIL]${NC} Cannot reach server: ${SERVER_URL}"
        echo -e "         Tried: ${health_url}"
        failed=1
    fi

    # Check if binary is available for download
    local download_url="${SERVER_URL}/api/agents/download/linux-${ARCH}"
    local http_code
    http_code=$(curl -sSL -H "ngrok-skip-browser-warning: true" -o /dev/null -w "%{http_code}" --connect-timeout 10 "$download_url" 2>/dev/null || echo "000")
    if [ "$http_code" = "200" ]; then
        echo -e "  ${GREEN}[OK]${NC} Agent binary available for linux-${ARCH}"
    else
        echo -e "  ${RED}[FAIL]${NC} Agent binary not available (HTTP ${http_code}): ${download_url}"
        failed=1
    fi

    if [ "$failed" -eq 1 ]; then
        echo -e "\n${RED}Pre-flight checks failed. Fix the issues above and retry.${NC}"
        exit 1
    fi

    echo -e "  ${GREEN}All pre-flight checks passed.${NC}\n"
}

# Download with retry and exponential backoff
download_with_retry() {
    local url="$1"
    local output="$2"
    local max_attempts=5
    local attempt=1

    while [ "$attempt" -le "$max_attempts" ]; do
        echo -e "  Download attempt ${attempt}/${max_attempts}..."
        if curl -sSL -f -H "ngrok-skip-browser-warning: true" --connect-timeout 30 --max-time 300 -o "$output" "$url" 2>/dev/null; then
            # Verify the download is not empty
            local file_size
            file_size=$(stat -c%s "$output" 2>/dev/null || stat -f%z "$output" 2>/dev/null || echo "0")
            if [ "$file_size" -gt 1000 ]; then
                echo -e "  ${GREEN}Downloaded successfully${NC} (${file_size} bytes)"
                return 0
            else
                echo -e "  ${YELLOW}Downloaded file too small (${file_size} bytes), retrying...${NC}"
            fi
        else
            echo -e "  ${YELLOW}Download failed, retrying...${NC}"
        fi

        if [ "$attempt" -lt "$max_attempts" ]; then
            local wait_time=$((2 ** attempt))
            echo -e "  Waiting ${wait_time}s before retry..."
            sleep "$wait_time"
        fi
        attempt=$((attempt + 1))
    done

    echo -e "  ${RED}All ${max_attempts} download attempts failed.${NC}"
    return 1
}

# Create service user
create_service_user() {
    if id "$SERVICE_USER" &>/dev/null; then
        echo -e "Service user '${SERVICE_USER}' already exists"
    else
        echo "Creating service user '${SERVICE_USER}'..."
        useradd -r -s /usr/sbin/nologin -d "$DATA_DIR" -M "$SERVICE_USER" 2>/dev/null || true
    fi
}

# Detect init system
detect_init_system() {
    if command -v systemctl &>/dev/null && systemctl --version &>/dev/null 2>&1; then
        echo "systemd"
    elif command -v rc-service &>/dev/null; then
        echo "openrc"
    elif [ -d /etc/init.d ]; then
        echo "sysvinit"
    else
        echo "none"
    fi
}

# Install systemd service
install_systemd_service() {
    echo "Installing systemd service..."
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=OdinForge Security Agent
Documentation=https://github.com/odinforge/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/odinforge-agent
EnvironmentFile=${CONFIG_DIR}/agent.env
Restart=always
RestartSec=10
User=root
WorkingDirectory=${DATA_DIR}

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${DATA_DIR} ${LOG_DIR}
PrivateTmp=yes

# Resource limits
LimitNOFILE=65536
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ${SERVICE_NAME}
    systemctl start ${SERVICE_NAME}
}

# Install OpenRC service
install_openrc_service() {
    echo "Installing OpenRC service..."
    cat > /etc/init.d/${SERVICE_NAME} << 'INITEOF'
#!/sbin/openrc-run

name="OdinForge Agent"
description="OdinForge Security Agent"
command="/usr/local/bin/odinforge-agent"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
start_stop_daemon_args="--env-file /etc/odinforge/agent.env"

depend() {
    need net
    after firewall
}
INITEOF
    chmod +x /etc/init.d/${SERVICE_NAME}
    rc-update add ${SERVICE_NAME} default
    rc-service ${SERVICE_NAME} start
}

# Install SysVinit service
install_sysvinit_service() {
    echo "Installing init.d service..."
    cat > /etc/init.d/${SERVICE_NAME} << 'INITEOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          odinforge-agent
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       OdinForge Security Agent
### END INIT INFO

DAEMON=/usr/local/bin/odinforge-agent
PIDFILE=/var/run/odinforge-agent.pid
ENVFILE=/etc/odinforge/agent.env

case "$1" in
    start)
        echo "Starting OdinForge Agent..."
        if [ -f "$ENVFILE" ]; then
            set -a; . "$ENVFILE"; set +a
        fi
        start-stop-daemon --start --background --make-pidfile --pidfile "$PIDFILE" --exec "$DAEMON"
        ;;
    stop)
        echo "Stopping OdinForge Agent..."
        start-stop-daemon --stop --pidfile "$PIDFILE"
        rm -f "$PIDFILE"
        ;;
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
    status)
        if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "OdinForge Agent is running"
        else
            echo "OdinForge Agent is not running"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
INITEOF
    chmod +x /etc/init.d/${SERVICE_NAME}
    update-rc.d ${SERVICE_NAME} defaults 2>/dev/null || true
    /etc/init.d/${SERVICE_NAME} start
}

# Post-install validation
validate_installation() {
    echo -e "\n${BLUE}Validating installation...${NC}"
    local checks_passed=0
    local checks_total=4

    # Check binary exists and is executable
    if [ -x "${INSTALL_DIR}/odinforge-agent" ]; then
        echo -e "  ${GREEN}[OK]${NC} Binary installed and executable"
        checks_passed=$((checks_passed + 1))
    else
        echo -e "  ${RED}[FAIL]${NC} Binary not found or not executable"
    fi

    # Check config exists
    if [ -f "${CONFIG_DIR}/agent.env" ]; then
        echo -e "  ${GREEN}[OK]${NC} Configuration file present"
        checks_passed=$((checks_passed + 1))
    else
        echo -e "  ${RED}[FAIL]${NC} Configuration file missing"
    fi

    # Check data directory exists
    if [ -d "${DATA_DIR}" ]; then
        echo -e "  ${GREEN}[OK]${NC} Data directory exists"
        checks_passed=$((checks_passed + 1))
    else
        echo -e "  ${RED}[FAIL]${NC} Data directory missing"
    fi

    # Check service is running (wait up to 15 seconds)
    local service_running=false
    for i in 1 2 3 4 5; do
        if systemctl is-active --quiet ${SERVICE_NAME} 2>/dev/null; then
            service_running=true
            break
        elif [ -f "/var/run/${SERVICE_NAME}.pid" ] && kill -0 "$(cat /var/run/${SERVICE_NAME}.pid 2>/dev/null)" 2>/dev/null; then
            service_running=true
            break
        fi
        sleep 3
    done

    if [ "$service_running" = "true" ]; then
        echo -e "  ${GREEN}[OK]${NC} Service is running"
        checks_passed=$((checks_passed + 1))
    else
        echo -e "  ${YELLOW}[WARN]${NC} Service may not be running yet (check logs)"
    fi

    echo -e "\n  Validation: ${checks_passed}/${checks_total} checks passed"

    if [ "$checks_passed" -lt 3 ]; then
        echo -e "  ${RED}Installation may have issues. Check logs:${NC}"
        echo "    journalctl -u ${SERVICE_NAME} -n 20 --no-pager"
        return 1
    fi

    return 0
}

# Configure firewall rules for agent communication
configure_firewall() {
    echo -e "\n${BLUE}Configuring firewall rules...${NC}"

    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
        ufw allow out 443/tcp comment "OdinForge agent HTTPS" 2>/dev/null || true
        ufw allow out 80/tcp comment "OdinForge agent HTTP" 2>/dev/null || true
        echo -e "  ${GREEN}[OK]${NC} UFW outbound rules configured (80/tcp, 443/tcp)"
    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --permanent --add-service=https 2>/dev/null || true
        firewall-cmd --permanent --add-service=http 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        echo -e "  ${GREEN}[OK]${NC} firewalld rules configured (http, https)"
    elif command -v iptables &>/dev/null; then
        # Only add if rule doesn't already exist
        if ! iptables -C OUTPUT -p tcp --dport 443 -m comment --comment "OdinForge agent" -j ACCEPT 2>/dev/null; then
            iptables -A OUTPUT -p tcp --dport 443 -m comment --comment "OdinForge agent" -j ACCEPT 2>/dev/null || true
        fi
        if ! iptables -C OUTPUT -p tcp --dport 80 -m comment --comment "OdinForge agent" -j ACCEPT 2>/dev/null; then
            iptables -A OUTPUT -p tcp --dport 80 -m comment --comment "OdinForge agent" -j ACCEPT 2>/dev/null || true
        fi
        echo -e "  ${GREEN}[OK]${NC} iptables outbound rules configured (80/tcp, 443/tcp)"
    else
        echo -e "  ${YELLOW}[SKIP]${NC} No active firewall detected (ufw/firewalld/iptables)"
    fi
}

# Remove firewall rules on uninstall
remove_firewall_rules() {
    echo "Removing firewall rules..."
    if command -v ufw &>/dev/null; then
        ufw delete allow out 443/tcp 2>/dev/null || true
        ufw delete allow out 80/tcp 2>/dev/null || true
    elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --permanent --remove-service=https 2>/dev/null || true
        firewall-cmd --permanent --remove-service=http 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
    elif command -v iptables &>/dev/null; then
        iptables -D OUTPUT -p tcp --dport 443 -m comment --comment "OdinForge agent" -j ACCEPT 2>/dev/null || true
        iptables -D OUTPUT -p tcp --dport 80 -m comment --comment "OdinForge agent" -j ACCEPT 2>/dev/null || true
    fi
}

# Check if agent is already installed
is_installed() {
    [ -f ${INSTALL_DIR}/odinforge-agent ]
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
        echo "  - Run pre-flight checks against ${SERVER_URL}"
        echo "  - Download agent binary from ${SERVER_URL}/api/agents/download/linux-${ARCH}"
        echo "  - Create service user '${SERVICE_USER}'"
        echo "  - Install binary to ${INSTALL_DIR}/odinforge-agent"
        echo "  - Create config directory ${CONFIG_DIR}"
        echo "  - Create data directory ${DATA_DIR}"
        echo "  - Create log directory ${LOG_DIR}"
        echo "  - Install and start service"
        echo "  - Validate installation"
        exit 0
    fi

    # Pre-flight checks
    preflight_checks

    # Download agent binary with retry
    echo "Downloading agent binary..."
    DOWNLOAD_URL="${SERVER_URL}/api/agents/download/linux-${ARCH}"
    if ! download_with_retry "$DOWNLOAD_URL" /tmp/odinforge-agent; then
        echo -e "${RED}Error: Failed to download agent after multiple attempts.${NC}"
        echo "URL: ${DOWNLOAD_URL}"
        echo ""
        echo "Troubleshooting:"
        echo "  1. Verify the server URL is correct"
        echo "  2. Check network connectivity: curl -v ${DOWNLOAD_URL}"
        echo "  3. Ensure agent binaries are built on the server"
        exit 1
    fi

    # Stop existing service if running
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true
    rc-service ${SERVICE_NAME} stop 2>/dev/null || true
    /etc/init.d/${SERVICE_NAME} stop 2>/dev/null || true

    # Create service user
    create_service_user

    # Install binary
    echo "Installing binary..."
    chmod +x /tmp/odinforge-agent
    mv /tmp/odinforge-agent ${INSTALL_DIR}/odinforge-agent

    # Create directories
    mkdir -p ${CONFIG_DIR}
    mkdir -p ${DATA_DIR}
    mkdir -p ${LOG_DIR}
    chown ${SERVICE_USER}:${SERVICE_USER} ${DATA_DIR} 2>/dev/null || true
    chown ${SERVICE_USER}:${SERVICE_USER} ${LOG_DIR} 2>/dev/null || true

    # Write config file
    echo "Writing configuration..."
    if [ "$AUTH_MODE" = "registration_token" ]; then
        cat > ${CONFIG_DIR}/agent.env << EOF
ODINFORGE_SERVER_URL=${SERVER_URL}
ODINFORGE_REGISTRATION_TOKEN=${REGISTRATION_TOKEN}
ODINFORGE_API_KEY_STORE_PATH=${DATA_DIR}/api_key
ODINFORGE_TENANT_ID=${TENANT_ID}
EOF
    else
        cat > ${CONFIG_DIR}/agent.env << EOF
ODINFORGE_SERVER_URL=${SERVER_URL}
ODINFORGE_API_KEY=${API_KEY}
ODINFORGE_TENANT_ID=${TENANT_ID}
EOF
    fi
    chmod 600 ${CONFIG_DIR}/agent.env

    # Detect and install appropriate service
    INIT_SYSTEM=$(detect_init_system)
    echo -e "Init system: ${GREEN}${INIT_SYSTEM}${NC}"

    case "$INIT_SYSTEM" in
        systemd)
            install_systemd_service
            ;;
        openrc)
            install_openrc_service
            ;;
        sysvinit)
            install_sysvinit_service
            ;;
        none)
            echo -e "${YELLOW}No supported init system found. Starting agent manually...${NC}"
            echo "You will need to configure auto-start manually."
            set -a; . ${CONFIG_DIR}/agent.env; set +a
            nohup ${INSTALL_DIR}/odinforge-agent > ${LOG_DIR}/agent.log 2>&1 &
            echo $! > /var/run/${SERVICE_NAME}.pid
            ;;
    esac

    # Validate the installation
    validate_installation

    # Configure firewall rules for agent communication
    configure_firewall

    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║         Agent installed and started successfully!         ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Quick commands:"
    if [ "$INIT_SYSTEM" = "systemd" ]; then
        echo "  Status:    systemctl status ${SERVICE_NAME}"
        echo "  Logs:      journalctl -u ${SERVICE_NAME} -f"
        echo "  Restart:   systemctl restart ${SERVICE_NAME}"
    else
        echo "  Status:    sudo ./install.sh status"
        echo "  Logs:      tail -f ${LOG_DIR}/agent.log"
    fi
    echo "  Uninstall: curl -sSL '${SERVER_URL}/api/agents/install.sh' | sudo bash -s -- uninstall"
}

# Uninstall the agent
do_uninstall() {
    echo -e "\n${BLUE}Uninstalling OdinForge Agent...${NC}"

    if [ "$DRY_RUN" = "true" ]; then
        echo -e "${YELLOW}[DRY RUN] Would perform the following actions:${NC}"
        echo "  - Stop and disable ${SERVICE_NAME} service"
        echo "  - Remove ${INSTALL_DIR}/odinforge-agent"
        echo "  - Remove ${CONFIG_DIR}/"
        echo "  - Remove ${DATA_DIR}/"
        echo "  - Remove ${LOG_DIR}/"
        echo "  - Remove service files"
        echo "  - Remove service user '${SERVICE_USER}'"
        exit 0
    fi

    # Remove firewall rules
    remove_firewall_rules

    # Stop and disable service (try all init systems)
    echo "Stopping service..."
    systemctl stop ${SERVICE_NAME} 2>/dev/null || true
    systemctl disable ${SERVICE_NAME} 2>/dev/null || true
    rc-service ${SERVICE_NAME} stop 2>/dev/null || true
    rc-update del ${SERVICE_NAME} 2>/dev/null || true
    /etc/init.d/${SERVICE_NAME} stop 2>/dev/null || true

    # Kill any remaining process
    if [ -f "/var/run/${SERVICE_NAME}.pid" ]; then
        kill "$(cat /var/run/${SERVICE_NAME}.pid)" 2>/dev/null || true
        rm -f "/var/run/${SERVICE_NAME}.pid"
    fi

    # Remove files
    echo "Removing files..."
    rm -f ${INSTALL_DIR}/odinforge-agent
    rm -f /etc/systemd/system/${SERVICE_NAME}.service
    rm -f /etc/init.d/${SERVICE_NAME}
    rm -rf ${CONFIG_DIR}
    rm -rf ${DATA_DIR}
    rm -rf ${LOG_DIR}

    # Remove service user
    userdel ${SERVICE_USER} 2>/dev/null || true

    # Reload systemd if available
    systemctl daemon-reload 2>/dev/null || true

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

    echo -e "Binary: ${GREEN}Installed${NC} (${INSTALL_DIR}/odinforge-agent)"

    # Show binary info
    local bin_size
    bin_size=$(stat -c%s "${INSTALL_DIR}/odinforge-agent" 2>/dev/null || stat -f%z "${INSTALL_DIR}/odinforge-agent" 2>/dev/null || echo "unknown")
    echo -e "Size:   ${bin_size} bytes"

    if [ -f ${CONFIG_DIR}/agent.env ]; then
        echo -e "Config: ${GREEN}Present${NC} (${CONFIG_DIR}/agent.env)"

        # Show non-sensitive config
        . ${CONFIG_DIR}/agent.env 2>/dev/null || true
        if [ -n "$ODINFORGE_SERVER_URL" ]; then
            echo -e "Server: ${GREEN}${ODINFORGE_SERVER_URL}${NC}"
        fi
        if [ -n "$ODINFORGE_TENANT_ID" ]; then
            echo -e "Tenant: ${GREEN}${ODINFORGE_TENANT_ID}${NC}"
        fi
    else
        echo -e "Config: ${YELLOW}Missing${NC}"
    fi

    # Check service user
    if id "${SERVICE_USER}" &>/dev/null; then
        echo -e "User:   ${GREEN}${SERVICE_USER}${NC}"
    else
        echo -e "User:   ${YELLOW}Not created (running as root)${NC}"
    fi

    echo ""

    # Check service status across init systems
    if systemctl is-active --quiet ${SERVICE_NAME} 2>/dev/null; then
        echo -e "Service: ${GREEN}Running${NC} (systemd)"
        echo ""
        echo "Recent logs:"
        journalctl -u ${SERVICE_NAME} -n 5 --no-pager 2>/dev/null || true
    elif systemctl is-enabled --quiet ${SERVICE_NAME} 2>/dev/null; then
        echo -e "Service: ${YELLOW}Enabled but not running${NC} (systemd)"
        echo ""
        echo "Recent error logs:"
        journalctl -u ${SERVICE_NAME} -n 10 --no-pager -p err 2>/dev/null || true
    elif [ -f "/var/run/${SERVICE_NAME}.pid" ] && kill -0 "$(cat /var/run/${SERVICE_NAME}.pid 2>/dev/null)" 2>/dev/null; then
        echo -e "Service: ${GREEN}Running${NC} (PID: $(cat /var/run/${SERVICE_NAME}.pid))"
    elif rc-service ${SERVICE_NAME} status 2>/dev/null | grep -q started; then
        echo -e "Service: ${GREEN}Running${NC} (OpenRC)"
    else
        echo -e "Service: ${RED}Not running${NC}"
        echo ""
        echo "Try starting:"
        echo "  systemctl start ${SERVICE_NAME}"
        echo "  # or check logs:"
        echo "  journalctl -u ${SERVICE_NAME} -n 20 --no-pager"
        if [ -f "${LOG_DIR}/agent.log" ]; then
            echo "  tail -20 ${LOG_DIR}/agent.log"
        fi
    fi

    # Network connectivity check
    echo ""
    if [ -n "$ODINFORGE_SERVER_URL" ]; then
        if curl -sSL -f --connect-timeout 5 -o /dev/null "${ODINFORGE_SERVER_URL}/healthz" 2>/dev/null; then
            echo -e "Server:  ${GREEN}Reachable${NC}"
        else
            echo -e "Server:  ${RED}Unreachable${NC}"
        fi
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
