package collector

import (
        "bytes"
        "os"
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
        case "windows":
                return getWindowsServices()
        default:
                return nil
        }
}

func getWindowsServices() []ServiceInfo {
        cmd := exec.Command("powershell", "-NoProfile", "-Command",
                "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 100 Name,Status | ForEach-Object { $_.Name + '|' + $_.Status }")
        var out bytes.Buffer
        cmd.Stdout = &out
        if err := cmd.Run(); err != nil {
                return getWindowsServicesFromCmd()
        }

        var services []ServiceInfo
        lines := strings.Split(out.String(), "\n")

        for _, line := range lines {
                line = strings.TrimSpace(line)
                if line == "" {
                        continue
                }
                parts := strings.Split(line, "|")
                if len(parts) >= 1 && parts[0] != "" {
                        status := "running"
                        if len(parts) >= 2 {
                                status = strings.ToLower(parts[1])
                        }
                        services = append(services, ServiceInfo{
                                Name:   parts[0],
                                Status: status,
                        })
                }
        }

        if len(services) > 100 {
                services = services[:100]
        }
        return services
}

func getWindowsServicesFromCmd() []ServiceInfo {
        cmd := exec.Command("cmd", "/c", "sc", "query", "type=", "service", "state=", "running")
        var out bytes.Buffer
        cmd.Stdout = &out
        if err := cmd.Run(); err != nil {
                return getWindowsServicesFromWMIC()
        }

        var services []ServiceInfo
        lines := strings.Split(out.String(), "\n")
        var currentName string

        for _, line := range lines {
                line = strings.TrimSpace(line)
                if strings.HasPrefix(line, "SERVICE_NAME:") {
                        currentName = strings.TrimSpace(strings.TrimPrefix(line, "SERVICE_NAME:"))
                } else if strings.HasPrefix(line, "STATE") && currentName != "" {
                        if strings.Contains(line, "RUNNING") {
                                services = append(services, ServiceInfo{
                                        Name:   currentName,
                                        Status: "running",
                                })
                        }
                        currentName = ""
                }
        }

        if len(services) > 100 {
                services = services[:100]
        }
        return services
}

func getWindowsServicesFromWMIC() []ServiceInfo {
        cmd := exec.Command("wmic", "service", "where", "State='Running'", "get", "Name,ProcessId", "/format:csv")
        var out bytes.Buffer
        cmd.Stdout = &out
        if err := cmd.Run(); err != nil {
                return nil
        }

        var services []ServiceInfo
        lines := strings.Split(out.String(), "\n")

        for _, line := range lines {
                line = strings.TrimSpace(line)
                if line == "" || strings.HasPrefix(line, "Node,") {
                        continue
                }
                fields := strings.Split(line, ",")
                if len(fields) >= 3 {
                        name := fields[1]
                        pid := fields[2]
                        if name != "" && name != "Name" {
                                services = append(services, ServiceInfo{
                                        Name:   name,
                                        Status: "running",
                                        PID:    pid,
                                })
                        }
                }
        }

        if len(services) > 100 {
                services = services[:100]
        }
        return services
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
                return getLinuxServicesFromProc()
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

func getLinuxServicesFromProc() []ServiceInfo {
        entries, err := os.ReadDir("/proc")
        if err != nil {
                return nil
        }

        seen := make(map[string]bool)
        var services []ServiceInfo
        daemons := regexp.MustCompile(`d$|server$|daemon$|svc$`)

        for _, entry := range entries {
                pidStr := entry.Name()
                if len(pidStr) == 0 || pidStr[0] < '0' || pidStr[0] > '9' {
                        continue
                }

                commPath := "/proc/" + pidStr + "/comm"
                comm, err := os.ReadFile(commPath)
                if err != nil {
                        continue
                }

                name := strings.TrimSpace(string(comm))
                if name == "" || seen[name] {
                        continue
                }

                if daemons.MatchString(name) || strings.HasSuffix(name, "-server") ||
                        strings.HasSuffix(name, "-agent") || strings.Contains(name, "nginx") ||
                        strings.Contains(name, "apache") || strings.Contains(name, "mysql") ||
                        strings.Contains(name, "postgres") || strings.Contains(name, "redis") ||
                        strings.Contains(name, "mongo") || strings.Contains(name, "node") ||
                        strings.Contains(name, "python") || strings.Contains(name, "java") ||
                        strings.Contains(name, "docker") || strings.Contains(name, "containerd") {
                        seen[name] = true
                        services = append(services, ServiceInfo{
                                Name:   name,
                                Status: "running",
                                PID:    pidStr,
                        })
                }
        }

        if len(services) > 100 {
                services = services[:100]
        }
        return services
}
