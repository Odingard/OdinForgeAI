package collector

import (
        "bytes"
        "os"
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
                return getLinuxPortsFromProc()
        }

        return parseNetstatOutput(out.String())
}

func getLinuxPortsFromProc() []PortInfo {
        var ports []PortInfo
        seen := make(map[int]bool)

        tcpPorts := parseProcNetTCP("/proc/net/tcp")
        for _, p := range tcpPorts {
                if !seen[p.Port] {
                        seen[p.Port] = true
                        ports = append(ports, p)
                }
        }

        tcp6Ports := parseProcNetTCP("/proc/net/tcp6")
        for _, p := range tcp6Ports {
                if !seen[p.Port] {
                        seen[p.Port] = true
                        ports = append(ports, p)
                }
        }

        if len(ports) > 200 {
                ports = ports[:200]
        }
        return ports
}

func parseProcNetTCP(path string) []PortInfo {
        data, err := os.ReadFile(path)
        if err != nil {
                return nil
        }

        var ports []PortInfo
        lines := strings.Split(string(data), "\n")

        for i, line := range lines {
                if i == 0 {
                        continue
                }
                line = strings.TrimSpace(line)
                if line == "" {
                        continue
                }

                fields := strings.Fields(line)
                if len(fields) < 4 {
                        continue
                }

                state := fields[3]
                if state != "0A" {
                        continue
                }

                localAddr := fields[1]
                colonIdx := strings.LastIndex(localAddr, ":")
                if colonIdx < 0 {
                        continue
                }

                portHex := localAddr[colonIdx+1:]
                port := hexToInt(portHex)
                if port <= 0 || port > 65535 {
                        continue
                }

                addrHex := localAddr[:colonIdx]
                addr := parseHexIP(addrHex)

                inode := ""
                if len(fields) >= 10 {
                        inode = fields[9]
                }

                pid, process := findProcessByInode(inode)

                ports = append(ports, PortInfo{
                        Port:     port,
                        Protocol: "tcp",
                        Process:  process,
                        PID:      pid,
                        Address:  addr,
                })
        }

        return ports
}


func hexToInt(hex string) int {
        result := 0
        for i := 0; i < len(hex); i++ {
                c := hex[i]
                var val int
                if c >= '0' && c <= '9' {
                        val = int(c - '0')
                } else if c >= 'A' && c <= 'F' {
                        val = int(c - 'A' + 10)
                } else if c >= 'a' && c <= 'f' {
                        val = int(c - 'a' + 10)
                } else {
                        return 0
                }
                result = result*16 + val
        }
        return result
}

func parseHexIP(hex string) string {
        if len(hex) == 8 {
                a := hexToInt(hex[6:8])
                b := hexToInt(hex[4:6])
                c := hexToInt(hex[2:4])
                d := hexToInt(hex[0:2])
                if a == 0 && b == 0 && c == 0 && d == 0 {
                        return "*"
                }
                return strconv.Itoa(a) + "." + strconv.Itoa(b) + "." + strconv.Itoa(c) + "." + strconv.Itoa(d)
        }
        if len(hex) == 32 {
                if hex == "00000000000000000000000000000000" {
                        return "*"
                }
                return "::"
        }
        return "*"
}

func findProcessByInode(inode string) (string, string) {
        if inode == "" || inode == "0" {
                return "", ""
        }

        fdTarget := "socket:[" + inode + "]"

        entries, err := os.ReadDir("/proc")
        if err != nil {
                return "", ""
        }

        for _, entry := range entries {
                name := entry.Name()
                if len(name) == 0 || name[0] < '0' || name[0] > '9' {
                        continue
                }

                fdPath := "/proc/" + name + "/fd"
                fdEntries, err := os.ReadDir(fdPath)
                if err != nil {
                        continue
                }

                for _, fdEntry := range fdEntries {
                        link, err := os.Readlink(fdPath + "/" + fdEntry.Name())
                        if err != nil {
                                continue
                        }
                        if link == fdTarget {
                                comm, _ := os.ReadFile("/proc/" + name + "/comm")
                                return name, strings.TrimSpace(string(comm))
                        }
                }
        }

        return "", ""
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
