package installer

import (
        "os"
        "os/exec"
        "runtime"
        "strings"
)

type Environment string

const (
        EnvDocker     Environment = "docker"
        EnvKubernetes Environment = "kubernetes"
        EnvSystemd    Environment = "systemd"
        EnvLaunchd    Environment = "launchd"
        EnvWindows    Environment = "windows"
        EnvUnknown    Environment = "unknown"
)

type DetectionResult struct {
        Environment   Environment
        IsContainer   bool
        IsRoot        bool
        Hostname      string
        OS            string
        Arch          string
        InitSystem    string
        CanAutoInstall bool
        Reason        string
}

func Detect() DetectionResult {
        result := DetectionResult{
                OS:       runtime.GOOS,
                Arch:     runtime.GOARCH,
                IsRoot:   isRoot(),
                Hostname: getHostname(),
        }

        // Check for container environments first
        if isKubernetes() {
                result.Environment = EnvKubernetes
                result.IsContainer = true
                result.CanAutoInstall = false
                result.Reason = "Running in Kubernetes - use kubectl apply with provided manifests"
                return result
        }

        if isDocker() {
                result.Environment = EnvDocker
                result.IsContainer = true
                result.CanAutoInstall = false
                result.Reason = "Running in Docker - use docker-compose with provided configuration"
                return result
        }

        // Check for native OS environments
        switch runtime.GOOS {
        case "linux":
                result.InitSystem = detectLinuxInit()
                if result.InitSystem == "systemd" {
                        result.Environment = EnvSystemd
                        result.CanAutoInstall = result.IsRoot
                        if !result.IsRoot {
                                result.Reason = "Root privileges required for systemd installation"
                        }
                } else {
                        result.Environment = EnvUnknown
                        result.CanAutoInstall = false
                        result.Reason = "Unsupported init system: " + result.InitSystem
                }

        case "darwin":
                result.Environment = EnvLaunchd
                result.InitSystem = "launchd"
                result.CanAutoInstall = result.IsRoot
                if !result.IsRoot {
                        result.Reason = "Root privileges required for launchd installation"
                }

        case "windows":
                result.Environment = EnvWindows
                result.InitSystem = "windows-service"
                result.CanAutoInstall = result.IsRoot
                if !result.CanAutoInstall {
                        result.Reason = "Administrator privileges required for Windows service installation"
                }

        default:
                result.Environment = EnvUnknown
                result.CanAutoInstall = false
                result.Reason = "Unsupported operating system: " + runtime.GOOS
        }

        return result
}

func getHostname() string {
        hostname, err := os.Hostname()
        if err != nil {
                return "unknown"
        }
        return hostname
}

func isDocker() bool {
        // Check for .dockerenv file
        if _, err := os.Stat("/.dockerenv"); err == nil {
                return true
        }

        // Check cgroup for docker
        if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
                content := string(data)
                if strings.Contains(content, "docker") || strings.Contains(content, "containerd") {
                        return true
                }
        }

        // Check for container environment variable
        if os.Getenv("container") == "docker" {
                return true
        }

        return false
}

func isKubernetes() bool {
        // Check for Kubernetes service account
        if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/token"); err == nil {
                return true
        }

        // Check for Kubernetes environment variables
        if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
                return true
        }

        return false
}

func detectLinuxInit() string {
        // Check if systemd is running
        if _, err := os.Stat("/run/systemd/system"); err == nil {
                return "systemd"
        }

        // Check process 1
        if data, err := os.ReadFile("/proc/1/comm"); err == nil {
                comm := strings.TrimSpace(string(data))
                switch comm {
                case "systemd":
                        return "systemd"
                case "init":
                        // Could be sysvinit or upstart
                        if _, err := exec.LookPath("initctl"); err == nil {
                                return "upstart"
                        }
                        return "sysvinit"
                case "openrc-init":
                        return "openrc"
                }
        }

        return "unknown"
}

func (e Environment) String() string {
        return string(e)
}

func (e Environment) DisplayName() string {
        switch e {
        case EnvDocker:
                return "Docker Container"
        case EnvKubernetes:
                return "Kubernetes Pod"
        case EnvSystemd:
                return "Linux (systemd)"
        case EnvLaunchd:
                return "macOS (launchd)"
        case EnvWindows:
                return "Windows Service"
        default:
                return "Unknown"
        }
}
