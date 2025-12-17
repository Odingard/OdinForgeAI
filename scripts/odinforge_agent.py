#!/usr/bin/env python3
"""
OdinForge Endpoint Agent
Collects system telemetry and sends to OdinForge for security analysis.

Installation:
    pip install requests psutil

Usage:
    python odinforge_agent.py

Environment Variables:
    ODINFORGE_URL - OdinForge server URL (default: http://localhost:5000)
    ODINFORGE_API_KEY - Agent API key (required)
    TELEMETRY_INTERVAL - Seconds between telemetry sends (default: 300)
"""

import os
import sys
import json
import socket
import platform
import subprocess
import time
import logging
from datetime import datetime

try:
    import requests
except ImportError:
    print("Error: 'requests' package not installed. Run: pip install requests")
    sys.exit(1)

# Configuration
ODINFORGE_URL = os.environ.get("ODINFORGE_URL", "http://localhost:5000")
API_KEY = os.environ.get("ODINFORGE_API_KEY", "")
TELEMETRY_INTERVAL = int(os.environ.get("TELEMETRY_INTERVAL", "300"))
REQUIRE_HTTPS = os.environ.get("ODINFORGE_REQUIRE_HTTPS", "true").lower() == "true"
MAX_RETRIES = 5
INITIAL_BACKOFF = 30

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - OdinForge Agent - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def get_system_info():
    """Collect system information."""
    try:
        return {
            "hostname": socket.gethostname(),
            "platform": platform.system().lower(),
            "platformVersion": platform.release(),
            "kernel": platform.version(),
            "architecture": platform.machine(),
            "uptime": get_uptime(),
            "pythonVersion": platform.python_version(),
        }
    except Exception as e:
        logger.warning(f"Error collecting system info: {e}")
        return {"error": str(e)}


def get_uptime():
    """Get system uptime in seconds."""
    try:
        if platform.system() == "Linux":
            with open('/proc/uptime', 'r') as f:
                return int(float(f.read().split()[0]))
        elif platform.system() == "Darwin":
            result = subprocess.run(
                ["sysctl", "-n", "kern.boottime"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                import re
                match = re.search(r'sec = (\d+)', result.stdout)
                if match:
                    boot_time = int(match.group(1))
                    return int(time.time() - boot_time)
        return 0
    except Exception:
        return 0


def get_resource_metrics():
    """Collect resource usage metrics."""
    try:
        import psutil
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        return {
            "cpuUsage": psutil.cpu_percent(interval=1),
            "cpuCount": psutil.cpu_count(),
            "memoryTotal": mem.total,
            "memoryUsed": mem.used,
            "memoryPercent": mem.percent,
            "diskTotal": disk.total,
            "diskUsed": disk.used,
            "diskPercent": disk.percent,
        }
    except ImportError:
        logger.warning("psutil not installed - resource metrics unavailable")
        return {"error": "psutil not installed. Run: pip install psutil"}
    except Exception as e:
        logger.warning(f"Error collecting resource metrics: {e}")
        return {"error": str(e)}


def get_open_ports():
    """Get list of open ports."""
    ports = []
    try:
        if platform.system() == "Linux":
            result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        addr = parts[3]
                        if ':' in addr:
                            port = addr.split(':')[-1]
                            try:
                                ports.append({
                                    "port": int(port),
                                    "protocol": "tcp",
                                    "state": "listen",
                                    "localAddress": addr,
                                })
                            except ValueError:
                                continue
        elif platform.system() == "Darwin":
            result = subprocess.run(
                ["lsof", "-i", "-P", "-n"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n')[1:]:
                if "LISTEN" in line:
                    parts = line.split()
                    if len(parts) >= 9:
                        addr = parts[8]
                        if ':' in addr:
                            port = addr.split(':')[-1]
                            try:
                                ports.append({
                                    "port": int(port),
                                    "protocol": "tcp",
                                    "state": "listen",
                                    "localAddress": addr,
                                    "process": parts[0],
                                })
                            except ValueError:
                                continue
    except Exception as e:
        logger.warning(f"Error getting ports: {e}")
    return ports


def get_running_services():
    """Get list of running services with versions."""
    services = []
    
    # Common service checks
    service_checks = [
        ("apache2", ["apache2", "-v"]),
        ("httpd", ["httpd", "-v"]),
        ("nginx", ["nginx", "-v"]),
        ("mysql", ["mysql", "--version"]),
        ("postgresql", ["psql", "--version"]),
        ("redis", ["redis-server", "--version"]),
        ("mongodb", ["mongod", "--version"]),
        ("docker", ["docker", "--version"]),
        ("node", ["node", "--version"]),
        ("python", ["python3", "--version"]),
        ("sshd", ["ssh", "-V"]),
    ]
    
    for name, cmd in service_checks:
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=5
            )
            output = (result.stdout + result.stderr).strip()
            if output and result.returncode == 0:
                version = output.split('\n')[0][:100]
                services.append({
                    "name": name,
                    "version": version,
                    "status": "detected",
                })
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        except Exception:
            pass
    
    return services


def get_network_connections():
    """Get active network connections."""
    connections = []
    try:
        import psutil
        for conn in psutil.net_connections(kind='inet')[:50]:
            if conn.status == 'ESTABLISHED':
                connections.append({
                    "localAddress": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remoteAddress": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status,
                    "pid": conn.pid,
                })
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"Error getting network connections: {e}")
    return connections


def detect_security_issues():
    """Detect potential security issues."""
    findings = []
    
    # Only run on Linux
    if platform.system() != "Linux":
        return findings
    
    # Check for root SSH login
    try:
        with open('/etc/ssh/sshd_config', 'r') as f:
            config = f.read()
            if 'PermitRootLogin yes' in config or 'PermitRootLogin without-password' in config:
                findings.append({
                    "type": "weak_config",
                    "severity": "high",
                    "title": "SSH Root Login Enabled",
                    "description": "SSH is configured to allow root login, which is a security risk. Attackers targeting root directly can gain full system access.",
                    "affectedComponent": "sshd",
                    "recommendation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd",
                })
            
            if 'PasswordAuthentication yes' in config:
                findings.append({
                    "type": "weak_config",
                    "severity": "medium",
                    "title": "SSH Password Authentication Enabled",
                    "description": "SSH allows password authentication which is vulnerable to brute force attacks.",
                    "affectedComponent": "sshd",
                    "recommendation": "Disable password authentication and use key-based auth only",
                })
    except FileNotFoundError:
        pass
    except PermissionError:
        pass
    
    # Check for world-writable files in /etc
    try:
        result = subprocess.run(
            ["find", "/etc", "-type", "f", "-perm", "-o+w", "-maxdepth", "2"],
            capture_output=True, text=True, timeout=30
        )
        if result.stdout.strip():
            files = result.stdout.strip().split('\n')[:10]
            findings.append({
                "type": "weak_permissions",
                "severity": "medium",
                "title": "World-Writable Configuration Files",
                "description": f"Found {len(files)} world-writable files in /etc: {', '.join(files[:3])}...",
                "affectedComponent": "filesystem",
                "recommendation": "Remove world-write permissions: chmod o-w <files>",
            })
    except Exception:
        pass
    
    # Check for outdated packages (Debian/Ubuntu)
    try:
        result = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True, text=True, timeout=60
        )
        upgradable = [l for l in result.stdout.split('\n') if 'security' in l.lower()]
        if len(upgradable) > 5:
            findings.append({
                "type": "outdated_software",
                "severity": "high",
                "title": f"{len(upgradable)} Security Updates Pending",
                "description": f"Multiple security updates are available for installed packages.",
                "affectedComponent": "system-packages",
                "recommendation": "Run 'apt update && apt upgrade' to install security updates",
            })
    except FileNotFoundError:
        pass  # Not a Debian-based system
    except Exception:
        pass
    
    # Check for common vulnerable software
    try:
        import psutil
        procs = {p.name(): p.cmdline() for p in psutil.process_iter(['name', 'cmdline'])}
        
        if 'telnetd' in procs:
            findings.append({
                "type": "insecure_service",
                "severity": "critical",
                "title": "Telnet Service Running",
                "description": "Telnet transmits data in plaintext including passwords. This is a critical security risk.",
                "affectedComponent": "telnetd",
                "recommendation": "Disable telnet and use SSH instead",
            })
        
        if 'vsftpd' in procs or 'proftpd' in procs:
            findings.append({
                "type": "insecure_service",
                "severity": "medium",
                "title": "FTP Service Detected",
                "description": "Traditional FTP transmits credentials in plaintext.",
                "affectedComponent": "ftp",
                "recommendation": "Use SFTP or FTPS instead of plain FTP",
            })
    except ImportError:
        pass
    except Exception:
        pass
    
    # Check firewall status
    try:
        result = subprocess.run(
            ["iptables", "-L", "-n"],
            capture_output=True, text=True, timeout=10
        )
        if "policy ACCEPT" in result.stdout and result.stdout.count("ACCEPT") > 5:
            findings.append({
                "type": "weak_config",
                "severity": "medium",
                "title": "Permissive Firewall Configuration",
                "description": "Firewall appears to have very permissive rules. Consider restricting traffic.",
                "affectedComponent": "iptables",
                "recommendation": "Implement least-privilege firewall rules",
            })
    except Exception:
        pass
    
    return findings


def send_telemetry():
    """Send telemetry to OdinForge."""
    if not API_KEY:
        logger.error("No API key configured. Set ODINFORGE_API_KEY environment variable.")
        return False
    
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }
    
    logger.info("Collecting telemetry data...")
    
    payload = {
        "systemInfo": get_system_info(),
        "resourceMetrics": get_resource_metrics(),
        "services": get_running_services(),
        "openPorts": get_open_ports(),
        "networkConnections": get_network_connections(),
        "securityFindings": detect_security_issues(),
        "collectedAt": datetime.now().isoformat(),
    }
    
    try:
        logger.info(f"Sending telemetry to {ODINFORGE_URL}...")
        response = requests.post(
            f"{ODINFORGE_URL}/api/agents/telemetry",
            headers=headers,
            json=payload,
            timeout=30
        )
        response.raise_for_status()
        result = response.json()
        logger.info(f"Telemetry sent successfully. Findings created: {result.get('findingsCreated', 0)}")
        return True
    except requests.exceptions.ConnectionError:
        logger.error(f"Cannot connect to OdinForge at {ODINFORGE_URL}")
        return False
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error: {e.response.status_code} - {e.response.text}")
        return False
    except Exception as e:
        logger.error(f"Error sending telemetry: {e}")
        return False


def send_heartbeat():
    """Send heartbeat to OdinForge."""
    if not API_KEY:
        return False
    
    headers = {"Authorization": f"Bearer {API_KEY}"}
    try:
        response = requests.post(
            f"{ODINFORGE_URL}/api/agents/heartbeat",
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        return True
    except Exception as e:
        logger.debug(f"Heartbeat failed: {e}")
        return False


def main():
    """Main agent loop."""
    print("=" * 60)
    print("  OdinForge Endpoint Security Agent")
    print("=" * 60)
    print(f"  Server URL: {ODINFORGE_URL}")
    print(f"  Telemetry Interval: {TELEMETRY_INTERVAL}s")
    print("=" * 60)
    
    if not API_KEY:
        print("\nERROR: No API key configured!")
        print("Set the ODINFORGE_API_KEY environment variable with your agent's API key.")
        print("You can register a new agent at the /agents page on your OdinForge instance.")
        sys.exit(1)
    
    # Security check: warn about insecure connections
    if REQUIRE_HTTPS and not ODINFORGE_URL.startswith("https://"):
        if ODINFORGE_URL.startswith("http://localhost") or ODINFORGE_URL.startswith("http://127.0.0.1"):
            logger.warning("Using insecure HTTP connection (localhost allowed for development)")
        else:
            print("\nSECURITY WARNING: Using insecure HTTP connection!")
            print("Set ODINFORGE_URL to an HTTPS endpoint or set ODINFORGE_REQUIRE_HTTPS=false")
            sys.exit(1)
    
    logger.info("Starting OdinForge agent...")
    
    # Initial telemetry send with retry
    retries = 0
    backoff = INITIAL_BACKOFF
    while not send_telemetry():
        retries += 1
        if retries > MAX_RETRIES:
            logger.error("Failed to connect to OdinForge after maximum retries")
            sys.exit(1)
        logger.warning(f"Retrying in {backoff}s (attempt {retries}/{MAX_RETRIES})")
        time.sleep(backoff)
        backoff = min(backoff * 2, 300)  # Cap at 5 minutes
    
    # Main loop
    consecutive_failures = 0
    while True:
        # Wait for next telemetry interval, sending heartbeats every minute
        heartbeat_interval = 60
        elapsed = 0
        
        while elapsed < TELEMETRY_INTERVAL:
            time.sleep(heartbeat_interval)
            elapsed += heartbeat_interval
            send_heartbeat()
            logger.debug("Heartbeat sent")
        
        # Send full telemetry with exponential backoff on failure
        if send_telemetry():
            consecutive_failures = 0
        else:
            consecutive_failures += 1
            if consecutive_failures >= MAX_RETRIES:
                logger.error("Too many consecutive failures, exiting")
                sys.exit(1)
            backoff = min(INITIAL_BACKOFF * (2 ** consecutive_failures), 300)
            logger.warning(f"Telemetry failed, backing off for {backoff}s")
            time.sleep(backoff)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")
        sys.exit(0)
