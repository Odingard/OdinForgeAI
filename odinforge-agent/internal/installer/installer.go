package installer

import (
        "fmt"
        "os"
        "os/exec"
        "path/filepath"
        "text/template"
)

type InstallConfig struct {
        ServerURL         string
        APIKey            string
        RegistrationToken string
        TenantID          string
        ConfigPath        string
        DataPath          string
        BinaryPath        string
        ServiceName       string
}

func DefaultInstallConfig() InstallConfig {
        return InstallConfig{
                TenantID:    "default",
                ConfigPath:  "/etc/odinforge/agent.yaml",
                DataPath:    "/var/lib/odinforge-agent",
                BinaryPath:  "/usr/local/bin/odinforge-agent",
                ServiceName: "odinforge-agent",
        }
}

type Installer interface {
        Install(cfg InstallConfig) error
        Uninstall(cfg InstallConfig) error
        Status(cfg InstallConfig) (ServiceStatus, error)
        Name() string
}

type ServiceStatus struct {
        Installed bool
        Running   bool
        Enabled   bool
        PID       int
        Message   string
}

func GetInstaller(env Environment) (Installer, error) {
        switch env {
        case EnvSystemd:
                return &SystemdInstaller{}, nil
        case EnvLaunchd:
                return &LaunchdInstaller{}, nil
        case EnvWindows:
                return &WindowsInstaller{}, nil
        default:
                return nil, fmt.Errorf("no installer available for environment: %s", env)
        }
}

// SystemdInstaller handles Linux systemd installations
type SystemdInstaller struct{}

func (s *SystemdInstaller) Name() string {
        return "systemd"
}

func (s *SystemdInstaller) Install(cfg InstallConfig) error {
        // Create directories
        dirs := []string{
                filepath.Dir(cfg.ConfigPath),
                cfg.DataPath,
        }
        for _, dir := range dirs {
                if err := os.MkdirAll(dir, 0755); err != nil {
                        return fmt.Errorf("failed to create directory %s: %w", dir, err)
                }
        }

        // Copy binary
        currentBinary, err := os.Executable()
        if err != nil {
                return fmt.Errorf("failed to get current executable: %w", err)
        }
        if currentBinary != cfg.BinaryPath {
                if err := copyFile(currentBinary, cfg.BinaryPath); err != nil {
                        return fmt.Errorf("failed to copy binary: %w", err)
                }
                if err := os.Chmod(cfg.BinaryPath, 0755); err != nil {
                        return fmt.Errorf("failed to set binary permissions: %w", err)
                }
        }

        // Create config file
        if err := createConfigFile(cfg); err != nil {
                return fmt.Errorf("failed to create config: %w", err)
        }

        // Create environment file
        envPath := filepath.Join(filepath.Dir(cfg.ConfigPath), "agent.env")
        if err := createEnvFile(cfg, envPath); err != nil {
                return fmt.Errorf("failed to create env file: %w", err)
        }

        // Create systemd service file
        servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", cfg.ServiceName)
        if err := createSystemdService(cfg, servicePath); err != nil {
                return fmt.Errorf("failed to create service file: %w", err)
        }

        // Create user if needed
        if err := createServiceUser(); err != nil {
                // Non-fatal, might already exist
                fmt.Printf("Note: Could not create service user: %v\n", err)
        }

        // Set ownership
        if err := exec.Command("chown", "-R", "odinforge:odinforge", cfg.DataPath).Run(); err != nil {
                fmt.Printf("Note: Could not set data directory ownership: %v\n", err)
        }

        // Reload systemd
        if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
                return fmt.Errorf("failed to reload systemd: %w", err)
        }

        // Enable service
        if err := exec.Command("systemctl", "enable", cfg.ServiceName).Run(); err != nil {
                return fmt.Errorf("failed to enable service: %w", err)
        }

        // Start service
        if err := exec.Command("systemctl", "start", cfg.ServiceName).Run(); err != nil {
                return fmt.Errorf("failed to start service: %w", err)
        }

        return nil
}

func (s *SystemdInstaller) Uninstall(cfg InstallConfig) error {
        // Stop service
        exec.Command("systemctl", "stop", cfg.ServiceName).Run()

        // Disable service
        exec.Command("systemctl", "disable", cfg.ServiceName).Run()

        // Remove service file
        servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", cfg.ServiceName)
        os.Remove(servicePath)

        // Reload systemd
        exec.Command("systemctl", "daemon-reload").Run()

        // Optionally remove binary (ask user first in CLI)
        // os.Remove(cfg.BinaryPath)

        return nil
}

func (s *SystemdInstaller) Status(cfg InstallConfig) (ServiceStatus, error) {
        status := ServiceStatus{}

        // Check if service file exists
        servicePath := fmt.Sprintf("/etc/systemd/system/%s.service", cfg.ServiceName)
        if _, err := os.Stat(servicePath); err == nil {
                status.Installed = true
        }

        // Check if enabled
        out, err := exec.Command("systemctl", "is-enabled", cfg.ServiceName).Output()
        if err == nil && string(out) == "enabled\n" {
                status.Enabled = true
        }

        // Check if running
        out, err = exec.Command("systemctl", "is-active", cfg.ServiceName).Output()
        if err == nil && string(out) == "active\n" {
                status.Running = true
        }

        // Get PID if running
        if status.Running {
                out, err = exec.Command("systemctl", "show", cfg.ServiceName, "--property=MainPID", "--value").Output()
                if err == nil {
                        fmt.Sscanf(string(out), "%d", &status.PID)
                }
        }

        return status, nil
}

// LaunchdInstaller handles macOS launchd installations
type LaunchdInstaller struct{}

func (l *LaunchdInstaller) Name() string {
        return "launchd"
}

func (l *LaunchdInstaller) Install(cfg InstallConfig) error {
        // Create directories
        dirs := []string{
                filepath.Dir(cfg.ConfigPath),
                cfg.DataPath,
                "/var/log/odinforge-agent",
        }
        for _, dir := range dirs {
                if err := os.MkdirAll(dir, 0755); err != nil {
                        return fmt.Errorf("failed to create directory %s: %w", dir, err)
                }
        }

        // Copy binary
        currentBinary, err := os.Executable()
        if err != nil {
                return fmt.Errorf("failed to get current executable: %w", err)
        }
        if currentBinary != cfg.BinaryPath {
                if err := copyFile(currentBinary, cfg.BinaryPath); err != nil {
                        return fmt.Errorf("failed to copy binary: %w", err)
                }
                if err := os.Chmod(cfg.BinaryPath, 0755); err != nil {
                        return fmt.Errorf("failed to set binary permissions: %w", err)
                }
        }

        // Create config file
        if err := createConfigFile(cfg); err != nil {
                return fmt.Errorf("failed to create config: %w", err)
        }

        // Create launchd plist
        plistPath := "/Library/LaunchDaemons/com.odinforge.agent.plist"
        if err := createLaunchdPlist(cfg, plistPath); err != nil {
                return fmt.Errorf("failed to create plist: %w", err)
        }

        // Load the service
        if err := exec.Command("launchctl", "load", plistPath).Run(); err != nil {
                return fmt.Errorf("failed to load service: %w", err)
        }

        return nil
}

func (l *LaunchdInstaller) Uninstall(cfg InstallConfig) error {
        plistPath := "/Library/LaunchDaemons/com.odinforge.agent.plist"

        // Unload the service
        exec.Command("launchctl", "unload", plistPath).Run()

        // Remove plist
        os.Remove(plistPath)

        return nil
}

func (l *LaunchdInstaller) Status(cfg InstallConfig) (ServiceStatus, error) {
        status := ServiceStatus{}

        plistPath := "/Library/LaunchDaemons/com.odinforge.agent.plist"
        if _, err := os.Stat(plistPath); err == nil {
                status.Installed = true
        }

        // Check if running using launchctl
        out, err := exec.Command("launchctl", "list", "com.odinforge.agent").Output()
        if err == nil && len(out) > 0 {
                status.Running = true
                status.Enabled = true
        }

        return status, nil
}

// WindowsInstaller handles Windows service installations
type WindowsInstaller struct{}

func (w *WindowsInstaller) Name() string {
        return "windows"
}

func (w *WindowsInstaller) Install(cfg InstallConfig) error {
        // Windows-specific paths
        cfg.ConfigPath = "C:\\ProgramData\\OdinForge\\agent.yaml"
        cfg.DataPath = "C:\\ProgramData\\OdinForge\\data"
        cfg.BinaryPath = "C:\\Program Files\\OdinForge\\odinforge-agent.exe"

        // Create directories
        dirs := []string{
                filepath.Dir(cfg.ConfigPath),
                cfg.DataPath,
                filepath.Dir(cfg.BinaryPath),
        }
        for _, dir := range dirs {
                if err := os.MkdirAll(dir, 0755); err != nil {
                        return fmt.Errorf("failed to create directory %s: %w", dir, err)
                }
        }

        // Copy binary
        currentBinary, err := os.Executable()
        if err != nil {
                return fmt.Errorf("failed to get current executable: %w", err)
        }
        if currentBinary != cfg.BinaryPath {
                if err := copyFile(currentBinary, cfg.BinaryPath); err != nil {
                        return fmt.Errorf("failed to copy binary: %w", err)
                }
        }

        // Create config file
        if err := createConfigFile(cfg); err != nil {
                return fmt.Errorf("failed to create config: %w", err)
        }

        // Create Windows service using sc.exe
        binPath := fmt.Sprintf("\"%s\" --config \"%s\"", cfg.BinaryPath, cfg.ConfigPath)
        cmd := exec.Command("sc.exe", "create", cfg.ServiceName,
                "binPath=", binPath,
                "DisplayName=", "OdinForge Security Agent",
                "start=", "auto",
                "obj=", "LocalSystem")
        if err := cmd.Run(); err != nil {
                return fmt.Errorf("failed to create service: %w", err)
        }

        // Set description
        exec.Command("sc.exe", "description", cfg.ServiceName,
                "OdinForge Security Agent - Telemetry and monitoring service").Run()

        // Start service
        if err := exec.Command("sc.exe", "start", cfg.ServiceName).Run(); err != nil {
                return fmt.Errorf("failed to start service: %w", err)
        }

        return nil
}

func (w *WindowsInstaller) Uninstall(cfg InstallConfig) error {
        // Stop service
        exec.Command("sc.exe", "stop", cfg.ServiceName).Run()

        // Delete service
        if err := exec.Command("sc.exe", "delete", cfg.ServiceName).Run(); err != nil {
                return fmt.Errorf("failed to delete service: %w", err)
        }

        return nil
}

func (w *WindowsInstaller) Status(cfg InstallConfig) (ServiceStatus, error) {
        status := ServiceStatus{}

        out, err := exec.Command("sc.exe", "query", cfg.ServiceName).Output()
        if err == nil {
                status.Installed = true
                outStr := string(out)
                if contains(outStr, "RUNNING") {
                        status.Running = true
                }
        }

        return status, nil
}

// Helper functions

func copyFile(src, dst string) error {
        input, err := os.ReadFile(src)
        if err != nil {
                return err
        }
        return os.WriteFile(dst, input, 0755)
}

func createServiceUser() error {
        // Check if user exists
        if err := exec.Command("id", "odinforge").Run(); err == nil {
                return nil // User exists
        }

        // Create system user
        return exec.Command("useradd", "--system", "--no-create-home",
                "--shell", "/usr/sbin/nologin", "odinforge").Run()
}

func createConfigFile(cfg InstallConfig) error {
        tmpl := `server:
  url: "{{.ServerURL}}"
  verify_tls: true

auth:
  mode: api_key
  tenant_id: "{{.TenantID}}"
{{if .APIKey}}  api_key: "{{.APIKey}}"
{{end}}{{if .RegistrationToken}}  registration_token: "{{.RegistrationToken}}"
  api_key_store_path: "{{.DataPath}}/api_key"
{{end}}
collection:
  telemetry_interval: 5m
  heartbeat_interval: 1m

buffer:
  path: "{{.DataPath}}/agent.queue.db"
  max_events: 50000

transport:
  timeout: 15s
  batch_size: 50
  compress: true

safety:
  require_https: true
`
        t, err := template.New("config").Parse(tmpl)
        if err != nil {
                return err
        }

        f, err := os.Create(cfg.ConfigPath)
        if err != nil {
                return err
        }
        defer f.Close()

        if err := os.Chmod(cfg.ConfigPath, 0600); err != nil {
                return err
        }

        return t.Execute(f, cfg)
}

func createEnvFile(cfg InstallConfig, path string) error {
        content := fmt.Sprintf("ODINFORGE_SERVER_URL=%s\nODINFORGE_TENANT_ID=%s\n",
                cfg.ServerURL, cfg.TenantID)

        if cfg.APIKey != "" {
                content += fmt.Sprintf("ODINFORGE_API_KEY=%s\n", cfg.APIKey)
        }
        if cfg.RegistrationToken != "" {
                content += fmt.Sprintf("ODINFORGE_REGISTRATION_TOKEN=%s\n", cfg.RegistrationToken)
                content += fmt.Sprintf("ODINFORGE_API_KEY_STORE_PATH=%s/api_key\n", cfg.DataPath)
        }

        if err := os.WriteFile(path, []byte(content), 0600); err != nil {
                return err
        }
        return nil
}

func createSystemdService(cfg InstallConfig, path string) error {
        tmpl := `[Unit]
Description=OdinForge Security Agent
Documentation=https://github.com/odinforge/agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=odinforge
Group=odinforge

ExecStart={{.BinaryPath}} --config {{.ConfigPath}}
ExecReload=/bin/kill -HUP $MAINPID

Restart=on-failure
RestartSec=10
TimeoutStopSec=30

EnvironmentFile=-/etc/odinforge/agent.env

StateDirectory=odinforge-agent
RuntimeDirectory=odinforge-agent
ConfigurationDirectory=odinforge

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
NoNewPrivileges=yes
ReadWritePaths={{.DataPath}}

CapabilityBoundingSet=
AmbientCapabilities=

SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallArchitectures=native

MemoryMax=256M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
`
        t, err := template.New("service").Parse(tmpl)
        if err != nil {
                return err
        }

        f, err := os.Create(path)
        if err != nil {
                return err
        }
        defer f.Close()

        return t.Execute(f, cfg)
}

func createLaunchdPlist(cfg InstallConfig, path string) error {
        tmpl := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.odinforge.agent</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>{{.BinaryPath}}</string>
        <string>--config</string>
        <string>{{.ConfigPath}}</string>
    </array>
    
    <key>EnvironmentVariables</key>
    <dict>
        <key>ODINFORGE_SERVER_URL</key>
        <string>{{.ServerURL}}</string>
        <key>ODINFORGE_API_KEY</key>
        <string>{{.APIKey}}</string>
        <key>ODINFORGE_TENANT_ID</key>
        <string>{{.TenantID}}</string>
    </dict>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
        <key>NetworkState</key>
        <true/>
    </dict>
    
    <key>ThrottleInterval</key>
    <integer>10</integer>
    
    <key>WorkingDirectory</key>
    <string>{{.DataPath}}</string>
    
    <key>StandardOutPath</key>
    <string>/var/log/odinforge-agent/agent.log</string>
    
    <key>StandardErrorPath</key>
    <string>/var/log/odinforge-agent/agent.error.log</string>
</dict>
</plist>
`
        t, err := template.New("plist").Parse(tmpl)
        if err != nil {
                return err
        }

        f, err := os.Create(path)
        if err != nil {
                return err
        }
        defer f.Close()

        return t.Execute(f, cfg)
}

func contains(s, substr string) bool {
        return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
        for i := 0; i <= len(s)-len(substr); i++ {
                if s[i:i+len(substr)] == substr {
                        return true
                }
        }
        return false
}
