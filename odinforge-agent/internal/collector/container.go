package collector

import (
        "bufio"
        "os"
        "runtime"
)

type ContainerInfo struct {
        IsContainer     bool   `json:"is_container"`
        Runtime         string `json:"runtime,omitempty"`
        ContainerID     string `json:"container_id,omitempty"`
        ImageID         string `json:"image_id,omitempty"`
        PodName         string `json:"pod_name,omitempty"`
        PodNamespace    string `json:"pod_namespace,omitempty"`
        PodUID          string `json:"pod_uid,omitempty"`
        ServiceAccount  string `json:"service_account,omitempty"`
        NodeName        string `json:"node_name,omitempty"`
        ClusterName     string `json:"cluster_name,omitempty"`
        Orchestrator    string `json:"orchestrator,omitempty"`
        CgroupPath      string `json:"cgroup_path,omitempty"`
        MemoryLimit     int64  `json:"memory_limit,omitempty"`
        CPULimit        string `json:"cpu_limit,omitempty"`
        Privileged      bool   `json:"privileged"`
        HostNetwork     bool   `json:"host_network"`
        HostPID         bool   `json:"host_pid"`
}

func GetContainerInfo() ContainerInfo {
        info := ContainerInfo{
                IsContainer: false,
                Privileged:  false,
                HostNetwork: false,
                HostPID:     false,
        }

        if runtime.GOOS != "linux" {
                return info
        }

        info.IsContainer = detectContainer()
        if !info.IsContainer {
                return info
        }

        info.Runtime = detectRuntime()
        info.ContainerID = getContainerID()
        info.CgroupPath = getCgroupPath()
        info.MemoryLimit = getMemoryLimit()
        info.CPULimit = getCPULimit()
        info.Privileged = detectPrivileged()
        info.HostNetwork = detectHostNetwork()
        info.HostPID = detectHostPID()

        if isKubernetes() {
                info.Orchestrator = "kubernetes"
                info.PodName = getEnvOrEmpty("HOSTNAME")
                info.PodNamespace = getKubeNamespace()
                info.PodUID = getEnvOrEmpty("POD_UID")
                info.ServiceAccount = getKubeServiceAccount()
                info.NodeName = getEnvOrEmpty("NODE_NAME")
                info.ClusterName = getEnvOrEmpty("CLUSTER_NAME")
        }

        return info
}

func detectContainer() bool {
        if _, err := os.Stat("/.dockerenv"); err == nil {
                return true
        }

        if _, err := os.Stat("/run/.containerenv"); err == nil {
                return true
        }

        cgroup := readFirstLine("/proc/1/cgroup")
        if containsAny(cgroup, []string{"docker", "kubepods", "containerd", "cri-o", "lxc", "podman"}) {
                return true
        }

        sched := readFirstLine("/proc/1/sched")
        if len(sched) > 0 && !hasPrefix(sched, "systemd") && !hasPrefix(sched, "init") {
                return true
        }

        mountinfo := readFile("/proc/1/mountinfo")
        if containsAny(mountinfo, []string{"/docker/", "/kubepods/", "/containerd/"}) {
                return true
        }

        return false
}

func detectRuntime() string {
        if _, err := os.Stat("/.dockerenv"); err == nil {
                return "docker"
        }

        if _, err := os.Stat("/run/.containerenv"); err == nil {
                return "podman"
        }

        cgroup := readFile("/proc/1/cgroup")
        if containsStr(cgroup, "containerd") {
                return "containerd"
        }
        if containsStr(cgroup, "cri-o") {
                return "cri-o"
        }
        if containsStr(cgroup, "docker") {
                return "docker"
        }
        if containsStr(cgroup, "lxc") {
                return "lxc"
        }
        if containsStr(cgroup, "podman") {
                return "podman"
        }

        return "unknown"
}

func getContainerID() string {
        cgroup := readFile("/proc/self/cgroup")
        lines := splitLines(cgroup)
        for _, line := range lines {
                if containsStr(line, "docker") || containsStr(line, "kubepods") || containsStr(line, "containerd") {
                        parts := splitBySlash(line)
                        if len(parts) > 0 {
                                id := parts[len(parts)-1]
                                id = trimPrefix(id, "docker-")
                                id = trimSuffix(id, ".scope")
                                if len(id) >= 12 {
                                        if len(id) > 64 {
                                                return id[:64]
                                        }
                                        return id
                                }
                        }
                }
        }

        mountinfo := readFile("/proc/self/mountinfo")
        lines = splitLines(mountinfo)
        for _, line := range lines {
                if containsStr(line, "/docker/containers/") {
                        idx := indexStr(line, "/docker/containers/")
                        if idx >= 0 {
                                rest := line[idx+19:]
                                endIdx := indexStr(rest, "/")
                                if endIdx > 0 && endIdx <= 64 {
                                        return rest[:endIdx]
                                }
                        }
                }
        }

        hostname := getEnvOrEmpty("HOSTNAME")
        if len(hostname) == 12 || len(hostname) == 64 {
                if isHexString(hostname) {
                        return hostname
                }
        }

        return ""
}

func getCgroupPath() string {
        cgroup := readFile("/proc/self/cgroup")
        lines := splitLines(cgroup)
        for _, line := range lines {
                parts := splitByColon(line)
                if len(parts) >= 3 {
                        return parts[2]
                }
        }
        return ""
}

func getMemoryLimit() int64 {
        cgroupV2 := readFirstLine("/sys/fs/cgroup/memory.max")
        if cgroupV2 != "" && cgroupV2 != "max" {
                return parseInt64(cgroupV2)
        }

        cgroupV1 := readFirstLine("/sys/fs/cgroup/memory/memory.limit_in_bytes")
        if cgroupV1 != "" {
                limit := parseInt64(cgroupV1)
                if limit > 0 && limit < 9223372036854771712 {
                        return limit
                }
        }

        return 0
}

func getCPULimit() string {
        cgroupV2Quota := readFirstLine("/sys/fs/cgroup/cpu.max")
        if cgroupV2Quota != "" && cgroupV2Quota != "max" {
                return cgroupV2Quota
        }

        quota := readFirstLine("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
        period := readFirstLine("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
        if quota != "" && quota != "-1" && period != "" {
                return quota + "/" + period
        }

        return ""
}

func detectPrivileged() bool {
        caps := readFile("/proc/self/status")
        lines := splitLines(caps)
        for _, line := range lines {
                if hasPrefix(line, "CapEff:") {
                        capVal := trimSpace(trimPrefix(line, "CapEff:"))
                        if capVal == "0000003fffffffff" || capVal == "000001ffffffffff" {
                                return true
                        }
                }
        }

        if _, err := os.Stat("/dev/sda"); err == nil {
                return true
        }

        return false
}

func detectHostNetwork() bool {
        containerNS := readLink("/proc/1/ns/net")
        hostNS := readLink("/proc/self/ns/net")

        if containerNS == "" || hostNS == "" {
                return false
        }

        cgroup := readFile("/proc/1/cgroup")
        if !containsAny(cgroup, []string{"docker", "kubepods", "containerd"}) {
                return containerNS == hostNS
        }

        return false
}

func detectHostPID() bool {
        if _, err := os.Stat("/proc/1/cmdline"); err == nil {
                cmdline := readFile("/proc/1/cmdline")
                if containsStr(cmdline, "systemd") || containsStr(cmdline, "/sbin/init") {
                        return true
                }
        }
        return false
}

func isKubernetes() bool {
        if getEnvOrEmpty("KUBERNETES_SERVICE_HOST") != "" {
                return true
        }
        if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount"); err == nil {
                return true
        }
        return false
}

func getKubeNamespace() string {
        if ns := getEnvOrEmpty("POD_NAMESPACE"); ns != "" {
                return ns
        }
        ns := readFirstLine("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
        return ns
}

func getKubeServiceAccount() string {
        if sa := getEnvOrEmpty("SERVICE_ACCOUNT"); sa != "" {
                return sa
        }
        token := readFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
        if token != "" {
                return "(token-present)"
        }
        return ""
}

func readFirstLine(path string) string {
        f, err := os.Open(path)
        if err != nil {
                return ""
        }
        defer f.Close()
        scanner := bufio.NewScanner(f)
        if scanner.Scan() {
                return scanner.Text()
        }
        return ""
}

func readFile(path string) string {
        data, err := os.ReadFile(path)
        if err != nil {
                return ""
        }
        return string(data)
}

func readLink(path string) string {
        target, err := os.Readlink(path)
        if err != nil {
                return ""
        }
        return target
}

func getEnvOrEmpty(key string) string {
        return os.Getenv(key)
}

func containsAny(s string, substrs []string) bool {
        for _, sub := range substrs {
                if containsStr(s, sub) {
                        return true
                }
        }
        return false
}

func containsStr(s, substr string) bool {
        return indexStr(s, substr) >= 0
}

func indexStr(s, substr string) int {
        for i := 0; i <= len(s)-len(substr); i++ {
                if s[i:i+len(substr)] == substr {
                        return i
                }
        }
        return -1
}

func hasPrefix(s, prefix string) bool {
        return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func trimPrefix(s, prefix string) string {
        if hasPrefix(s, prefix) {
                return s[len(prefix):]
        }
        return s
}

func trimSuffix(s, suffix string) string {
        if len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix {
                return s[:len(s)-len(suffix)]
        }
        return s
}

func trimSpace(s string) string {
        start := 0
        end := len(s)
        for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
                start++
        }
        for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
                end--
        }
        return s[start:end]
}

func splitLines(s string) []string {
        var lines []string
        start := 0
        for i := 0; i < len(s); i++ {
                if s[i] == '\n' {
                        lines = append(lines, s[start:i])
                        start = i + 1
                }
        }
        if start < len(s) {
                lines = append(lines, s[start:])
        }
        return lines
}

func splitBySlash(s string) []string {
        var parts []string
        start := 0
        for i := 0; i < len(s); i++ {
                if s[i] == '/' {
                        if i > start {
                                parts = append(parts, s[start:i])
                        }
                        start = i + 1
                }
        }
        if start < len(s) {
                parts = append(parts, s[start:])
        }
        return parts
}

func splitByColon(s string) []string {
        var parts []string
        start := 0
        for i := 0; i < len(s); i++ {
                if s[i] == ':' {
                        parts = append(parts, s[start:i])
                        start = i + 1
                }
        }
        if start < len(s) {
                parts = append(parts, s[start:])
        }
        return parts
}

func parseInt64(s string) int64 {
        s = trimSpace(s)
        if s == "" {
                return 0
        }
        var result int64
        for i := 0; i < len(s); i++ {
                if s[i] >= '0' && s[i] <= '9' {
                        result = result*10 + int64(s[i]-'0')
                } else {
                        break
                }
        }
        return result
}

func isHexString(s string) bool {
        if len(s) == 0 {
                return false
        }
        for i := 0; i < len(s); i++ {
                c := s[i]
                if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
                        return false
                }
        }
        return true
}
