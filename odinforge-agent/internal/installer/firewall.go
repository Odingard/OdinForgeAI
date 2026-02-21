package installer

import (
	"fmt"
	"net/url"
	"os/exec"
	"strings"
)

// FirewallManager detects and configures host firewall rules
// to allow agent outbound communication to the OdinForge server.
type FirewallManager struct {
	serverURL string
}

// NewFirewallManager creates a manager for the given server URL.
func NewFirewallManager(serverURL string) *FirewallManager {
	return &FirewallManager{serverURL: serverURL}
}

// DetectFirewall returns the active firewall tool name.
func (f *FirewallManager) DetectFirewall() string {
	// Check UFW (Ubuntu/Debian)
	if path, err := exec.LookPath("ufw"); err == nil && path != "" {
		out, err := exec.Command("ufw", "status").CombinedOutput()
		if err == nil && strings.Contains(string(out), "active") {
			return "ufw"
		}
	}

	// Check firewalld (RHEL/CentOS/Fedora)
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		if err := exec.Command("systemctl", "is-active", "--quiet", "firewalld").Run(); err == nil {
			return "firewalld"
		}
	}

	// Check iptables
	if _, err := exec.LookPath("iptables"); err == nil {
		return "iptables"
	}

	return "none"
}

// serverPort returns the port from the server URL (defaults to 443 for https, 80 for http).
func (f *FirewallManager) serverPort() string {
	u, err := url.Parse(f.serverURL)
	if err != nil {
		return "443"
	}
	if u.Port() != "" {
		return u.Port()
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}

// ConfigureRules detects the active firewall and adds outbound rules.
func (f *FirewallManager) ConfigureRules() error {
	fw := f.DetectFirewall()
	port := f.serverPort()

	switch fw {
	case "ufw":
		return f.configureUFW(port)
	case "firewalld":
		return f.configureFirewalld(port)
	case "iptables":
		return f.configureIPTables(port)
	default:
		return nil // no firewall active
	}
}

// RemoveRules detects the active firewall and removes outbound rules.
func (f *FirewallManager) RemoveRules() error {
	fw := f.DetectFirewall()
	port := f.serverPort()

	switch fw {
	case "ufw":
		return f.removeUFW(port)
	case "firewalld":
		return f.removeFirewalld(port)
	case "iptables":
		return f.removeIPTables(port)
	default:
		return nil
	}
}

func (f *FirewallManager) configureUFW(port string) error {
	comment := "OdinForge agent"
	exec.Command("ufw", "allow", "out", port+"/tcp", "comment", comment).Run()
	return nil
}

func (f *FirewallManager) removeUFW(port string) error {
	exec.Command("ufw", "delete", "allow", "out", port+"/tcp").Run()
	return nil
}

func (f *FirewallManager) configureFirewalld(port string) error {
	rule := fmt.Sprintf("rule family=\"ipv4\" port port=\"%s\" protocol=\"tcp\" accept", port)
	exec.Command("firewall-cmd", "--permanent", "--add-rich-rule="+rule).Run()
	exec.Command("firewall-cmd", "--reload").Run()
	return nil
}

func (f *FirewallManager) removeFirewalld(port string) error {
	rule := fmt.Sprintf("rule family=\"ipv4\" port port=\"%s\" protocol=\"tcp\" accept", port)
	exec.Command("firewall-cmd", "--permanent", "--remove-rich-rule="+rule).Run()
	exec.Command("firewall-cmd", "--reload").Run()
	return nil
}

func (f *FirewallManager) configureIPTables(port string) error {
	comment := "OdinForge agent"
	// Check if rule already exists
	if err := exec.Command("iptables", "-C", "OUTPUT", "-p", "tcp", "--dport", port,
		"-m", "comment", "--comment", comment, "-j", "ACCEPT").Run(); err != nil {
		// Rule doesn't exist, add it
		exec.Command("iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", port,
			"-m", "comment", "--comment", comment, "-j", "ACCEPT").Run()
	}
	return nil
}

func (f *FirewallManager) removeIPTables(port string) error {
	comment := "OdinForge agent"
	exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "--dport", port,
		"-m", "comment", "--comment", comment, "-j", "ACCEPT").Run()
	return nil
}
