package collector

import (
        "bytes"
        "os/exec"
        "regexp"
        "runtime"
        "strconv"
        "strings"
)

type PortInfo struct {
        Port     int    `json:"port"`
        Protocol string `json:"protocol"`
        Process  string `json:"process,omitempty"`
        PID      string `json:"pid,omitempty"`
        Address  string `json:"address,omitempty"`
}

func GetOpenPorts() []PortInfo {
        switch runtime.GOOS {
        case "darwin":
                return getMacOSPorts()
        case "linux":
                return getLinuxPorts()
        default:
                return nil
        }
}

func getMacOSPorts() []PortInfo {
        cmd := exec.Command("lsof", "-iTCP", "-sTCP:LISTEN", "-P", "-n")
        var out bytes.Buffer
        cmd.Stdout = &out
        if err := cmd.Run(); err != nil {
                return getMacOSPortsFromNetstat()
        }

        seen := make(map[int]bool)
        var ports []PortInfo
        lines := strings.Split(out.String(), "\n")
        portRegex := regexp.MustCompile(`:(\d+)\s*\(LISTEN\)`)

        for i, line := range lines {
                if i == 0 || strings.TrimSpace(line) == "" {
                        continue
                }
                fields := strings.Fields(line)
                if len(fields) >= 9 {
                        process := fields[0]
                        pid := fields[1]
                        address := fields[8]

                        matches := portRegex.FindStringSubmatch(address)
                        if len(matches) >= 2 {
                                port, err := strconv.Atoi(matches[1])
                                if err == nil && !seen[port] {
                                        seen[port] = true
                                        addr := "*"
                                        if idx := strings.LastIndex(address, ":"); idx > 0 {
                                                addr = address[:idx]
                                        }
                                        ports = append(ports, PortInfo{
                                                Port:     port,
                                                Protocol: "tcp",
                                                Process:  process,
                                                PID:      pid,
                                                Address:  addr,
                                        })
                                }
                        }
                }
        }

        if len(ports) > 200 {
                ports = ports[:200]
        }
        return ports
}

func getMacOSPortsFromNetstat() []PortInfo {
        cmd := exec.Command("netstat", "-an", "-p", "tcp")
        var out bytes.Buffer
        cmd.Stdout = &out
        if err := cmd.Run(); err != nil {
                return nil
        }

        return parseNetstatOutput(out.String())
}

func getLinuxPorts() []PortInfo {
        cmd := exec.Command("ss", "-tlnp")
        var out bytes.Buffer
        cmd.Stdout = &out
        if err := cmd.Run(); err != nil {
                return getLinuxPortsFromNetstat()
        }

        seen := make(map[int]bool)
        var ports []PortInfo
        lines := strings.Split(out.String(), "\n")

        for i, line := range lines {
                if i == 0 || strings.TrimSpace(line) == "" {
                        continue
                }
                fields := strings.Fields(line)
                if len(fields) >= 4 && strings.Contains(fields[0], "LISTEN") {
                        local := fields[3]
                        if idx := strings.LastIndex(local, ":"); idx >= 0 {
                                portStr := local[idx+1:]
                                port, err := strconv.Atoi(portStr)
                                if err == nil && !seen[port] {
                                        seen[port] = true
                                        addr := local[:idx]
                                        if addr == "" || addr == "0.0.0.0" || addr == "::" {
                                                addr = "*"
                                        }
                                        process := ""
                                        pid := ""
                                        if len(fields) >= 6 {
                                                procInfo := fields[5]
                                                if strings.Contains(procInfo, "users:") {
                                                        re := regexp.MustCompile(`\("([^"]+)",pid=(\d+)`)
                                                        matches := re.FindStringSubmatch(procInfo)
                                                        if len(matches) >= 3 {
                                                                process = matches[1]
                                                                pid = matches[2]
                                                        }
                                                }
                                        }
                                        ports = append(ports, PortInfo{
                                                Port:     port,
                                                Protocol: "tcp",
                                                Process:  process,
                                                PID:      pid,
                                                Address:  addr,
                                        })
                                }
                        }
                }
        }

        if len(ports) > 200 {
                ports = ports[:200]
        }
        return ports
}

func getLinuxPortsFromNetstat() []PortInfo {
        cmd := exec.Command("netstat", "-tlnp")
        var out bytes.Buffer
        cmd.Stdout = &out
        if err := cmd.Run(); err != nil {
                return nil
        }

        return parseNetstatOutput(out.String())
}

func parseNetstatOutput(output string) []PortInfo {
        seen := make(map[int]bool)
        var ports []PortInfo
        lines := strings.Split(output, "\n")

        for _, line := range lines {
                if !strings.Contains(line, "LISTEN") {
                        continue
                }
                fields := strings.Fields(line)
                for _, field := range fields {
                        var port int
                        var found bool

                        // macOS format: 127.0.0.1.5000 or *.5000 (dot-delimited, port is last segment)
                        if strings.Contains(field, ".") {
                                parts := strings.Split(field, ".")
                                if len(parts) >= 2 {
                                        portStr := parts[len(parts)-1]
                                        p, err := strconv.Atoi(portStr)
                                        if err == nil && p > 0 && p < 65536 {
                                                port = p
                                                found = true
                                        }
                                }
                        }

                        // Linux format: 0.0.0.0:5000 or :::5000 (colon-delimited)
                        if !found {
                                if idx := strings.LastIndex(field, ":"); idx >= 0 {
                                        portStr := field[idx+1:]
                                        p, err := strconv.Atoi(portStr)
                                        if err == nil && p > 0 && p < 65536 {
                                                port = p
                                                found = true
                                        }
                                }
                        }

                        if found && !seen[port] {
                                seen[port] = true
                                ports = append(ports, PortInfo{
                                        Port:     port,
                                        Protocol: "tcp",
                                        Address:  "*",
                                })
                                break
                        }
                }
        }

        if len(ports) > 200 {
                ports = ports[:200]
        }
        return ports
}
