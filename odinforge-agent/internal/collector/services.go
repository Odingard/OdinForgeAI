package collector

import (
	"bytes"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

type ServiceInfo struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	PID    string `json:"pid,omitempty"`
}

func GetRunningServices() []ServiceInfo {
	switch runtime.GOOS {
	case "darwin":
		return getMacOSServices()
	case "linux":
		return getLinuxServices()
	default:
		return nil
	}
}

func getMacOSServices() []ServiceInfo {
	cmd := exec.Command("launchctl", "list")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil
	}

	var services []ServiceInfo
	lines := strings.Split(out.String(), "\n")
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			pid := fields[0]
			name := fields[2]
			if name != "" && !strings.HasPrefix(name, "0x") {
				status := "running"
				if pid == "-" {
					status = "stopped"
					pid = ""
				}
				if !strings.HasPrefix(name, "com.apple.") {
					services = append(services, ServiceInfo{
						Name:   name,
						Status: status,
						PID:    pid,
					})
				}
			}
		}
	}

	if len(services) > 100 {
		services = services[:100]
	}
	return services
}

func getLinuxServices() []ServiceInfo {
	cmd := exec.Command("systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return getLinuxServicesFromPs()
	}

	var services []ServiceInfo
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 1 {
			name := strings.TrimSuffix(fields[0], ".service")
			if name != "" {
				services = append(services, ServiceInfo{
					Name:   name,
					Status: "running",
				})
			}
		}
	}

	if len(services) > 100 {
		services = services[:100]
	}
	return services
}

func getLinuxServicesFromPs() []ServiceInfo {
	cmd := exec.Command("ps", "-eo", "comm", "--no-headers")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var services []ServiceInfo
	daemons := regexp.MustCompile(`d$|server$|daemon$|svc$`)

	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		name := strings.TrimSpace(line)
		if name == "" || seen[name] {
			continue
		}
		if daemons.MatchString(name) || strings.HasSuffix(name, "-server") {
			seen[name] = true
			services = append(services, ServiceInfo{
				Name:   name,
				Status: "running",
			})
		}
	}

	if len(services) > 100 {
		services = services[:100]
	}
	return services
}
