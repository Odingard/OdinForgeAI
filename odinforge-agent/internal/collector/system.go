package collector

import (
        "bufio"
        "crypto/sha256"
        "encoding/hex"
        "os"
        "os/exec"
        "runtime"
        "strings"
)

type SystemInfo struct {
        Hostname     string `json:"hostname"`
        OS           string `json:"os"`
        Platform     string `json:"platform"`
        PlatformVer  string `json:"platform_version"`
        KernelVer    string `json:"kernel_version"`
        Arch         string `json:"arch"`
        BootTimeUnix uint64 `json:"boot_time_unix"`
        IsContainer  bool   `json:"is_container"`
        IsRoot       bool   `json:"is_root"`
}

func GetSystemInfo() (SystemInfo, error) {
        h, _ := os.Hostname()
        info := SystemInfo{
                Hostname:    h,
                OS:          runtime.GOOS,
                Arch:        runtime.GOARCH,
                IsContainer: isContainerEnv(),
                IsRoot:      os.Geteuid() == 0,
        }

        info.Platform, info.PlatformVer = getPlatformInfo()
        info.KernelVer = getKernelVersion()
        info.BootTimeUnix = getBootTime()

        return info, nil
}

func getPlatformInfo() (string, string) {
        if runtime.GOOS == "linux" {
                if data, err := os.ReadFile("/etc/os-release"); err == nil {
                        lines := strings.Split(string(data), "\n")
                        var id, version string
                        for _, line := range lines {
                                if strings.HasPrefix(line, "ID=") {
                                        id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
                                }
                                if strings.HasPrefix(line, "VERSION_ID=") {
                                        version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
                                }
                        }
                        if id != "" {
                                return id, version
                        }
                }
                return "linux", ""
        }
        if runtime.GOOS == "darwin" {
                out, err := exec.Command("sw_vers", "-productVersion").Output()
                if err == nil {
                        return "macos", strings.TrimSpace(string(out))
                }
                return "darwin", ""
        }
        if runtime.GOOS == "windows" {
                return "windows", ""
        }
        return runtime.GOOS, ""
}

func getKernelVersion() string {
        if runtime.GOOS == "linux" {
                out, err := exec.Command("uname", "-r").Output()
                if err == nil {
                        return strings.TrimSpace(string(out))
                }
                if data, err := os.ReadFile("/proc/version"); err == nil {
                        parts := strings.Fields(string(data))
                        if len(parts) >= 3 {
                                return parts[2]
                        }
                }
        }
        if runtime.GOOS == "darwin" {
                out, err := exec.Command("uname", "-r").Output()
                if err == nil {
                        return strings.TrimSpace(string(out))
                }
        }
        return ""
}

func getBootTime() uint64 {
        if runtime.GOOS == "linux" {
                f, err := os.Open("/proc/stat")
                if err != nil {
                        return 0
                }
                defer f.Close()
                scanner := bufio.NewScanner(f)
                for scanner.Scan() {
                        line := scanner.Text()
                        if strings.HasPrefix(line, "btime ") {
                                parts := strings.Fields(line)
                                if len(parts) >= 2 {
                                        var btime uint64
                                        for _, c := range parts[1] {
                                                if c >= '0' && c <= '9' {
                                                        btime = btime*10 + uint64(c-'0')
                                                }
                                        }
                                        return btime
                                }
                        }
                }
        }
        return 0
}

func isContainerEnv() bool {
        if runtime.GOOS != "linux" {
                return false
        }
        if _, err := os.Stat("/.dockerenv"); err == nil {
                return true
        }
        if _, err := os.Stat("/run/.containerenv"); err == nil {
                return true
        }
        if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
                return true
        }
        return false
}

// StableAgentID: best-effort stable ID.
// In containers, uses container ID if available; otherwise uses hostname-based hash.
func StableAgentID() string {
        containerID := getContainerIDForAgent()
        if containerID != "" {
                sum := sha256.Sum256([]byte(containerID + "|" + runtime.GOOS + "|" + runtime.GOARCH))
                return "agent_" + hex.EncodeToString(sum[:8])
        }

        h, _ := os.Hostname()
        machineID := getMachineID()
        if machineID != "" {
                sum := sha256.Sum256([]byte(machineID + "|" + runtime.GOOS + "|" + runtime.GOARCH))
                return "agent_" + hex.EncodeToString(sum[:8])
        }

        sum := sha256.Sum256([]byte(h + "|" + runtime.GOOS + "|" + runtime.GOARCH))
        return "agent_" + hex.EncodeToString(sum[:8])
}

func getContainerIDForAgent() string {
        if runtime.GOOS != "linux" {
                return ""
        }
        data, err := os.ReadFile("/proc/self/cgroup")
        if err != nil {
                return ""
        }
        lines := strings.Split(string(data), "\n")
        for _, line := range lines {
                if strings.Contains(line, "docker") || strings.Contains(line, "kubepods") || strings.Contains(line, "containerd") {
                        parts := strings.Split(line, "/")
                        if len(parts) > 0 {
                                id := parts[len(parts)-1]
                                id = strings.TrimPrefix(id, "docker-")
                                id = strings.TrimSuffix(id, ".scope")
                                if len(id) >= 12 {
                                        return id
                                }
                        }
                }
        }
        return ""
}

func getMachineID() string {
        if data, err := os.ReadFile("/etc/machine-id"); err == nil {
                return strings.TrimSpace(string(data))
        }
        if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
                return strings.TrimSpace(string(data))
        }
        return ""
}
