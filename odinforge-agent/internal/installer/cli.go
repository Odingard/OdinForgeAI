package installer

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type CLIOptions struct {
	ServerURL   string
	APIKey      string
	TenantID    string
	Force       bool
	DryRun      bool
	Interactive bool
}

func RunInstall(opts CLIOptions) error {
	fmt.Println("OdinForge Agent Installer")
	fmt.Println("=========================")
	fmt.Println()

	// Detect environment
	detection := Detect()
	printDetectionResult(detection)

	if !detection.CanAutoInstall {
		fmt.Printf("\nAuto-installation not available: %s\n", detection.Reason)
		printManualInstructions(detection)
		return nil
	}

	// Get installer for this environment
	installer, err := GetInstaller(detection.Environment)
	if err != nil {
		return fmt.Errorf("no installer for this environment: %w", err)
	}

	// Collect configuration interactively if needed
	cfg := DefaultInstallConfig()
	if opts.ServerURL != "" {
		cfg.ServerURL = opts.ServerURL
	}
	if opts.APIKey != "" {
		cfg.APIKey = opts.APIKey
	}
	if opts.TenantID != "" {
		cfg.TenantID = opts.TenantID
	}

	if opts.Interactive || cfg.ServerURL == "" || cfg.APIKey == "" {
		if err := promptForConfig(&cfg); err != nil {
			return err
		}
	}

	// Validate configuration
	if cfg.ServerURL == "" {
		return fmt.Errorf("server URL is required")
	}
	if cfg.APIKey == "" {
		return fmt.Errorf("API key is required")
	}

	// Confirm installation
	if !opts.Force && opts.Interactive {
		fmt.Println()
		fmt.Println("Installation Summary:")
		fmt.Printf("  Server URL:  %s\n", cfg.ServerURL)
		fmt.Printf("  Tenant ID:   %s\n", cfg.TenantID)
		fmt.Printf("  Binary:      %s\n", cfg.BinaryPath)
		fmt.Printf("  Config:      %s\n", cfg.ConfigPath)
		fmt.Printf("  Data:        %s\n", cfg.DataPath)
		fmt.Println()

		if !confirm("Proceed with installation?") {
			fmt.Println("Installation cancelled.")
			return nil
		}
	}

	if opts.DryRun {
		fmt.Println("\n[Dry Run] Would install with the above configuration.")
		return nil
	}

	// Perform installation
	fmt.Println("\nInstalling...")
	if err := installer.Install(cfg); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	fmt.Println("\nInstallation complete!")
	fmt.Printf("The OdinForge agent is now running as a %s service.\n", installer.Name())
	fmt.Println("\nUseful commands:")
	printServiceCommands(detection.Environment)

	return nil
}

func RunUninstall(opts CLIOptions) error {
	fmt.Println("OdinForge Agent Uninstaller")
	fmt.Println("===========================")
	fmt.Println()

	detection := Detect()
	installer, err := GetInstaller(detection.Environment)
	if err != nil {
		return fmt.Errorf("no installer for this environment: %w", err)
	}

	cfg := DefaultInstallConfig()

	// Check current status
	status, err := installer.Status(cfg)
	if err != nil {
		return fmt.Errorf("failed to check status: %w", err)
	}

	if !status.Installed {
		fmt.Println("OdinForge agent is not installed.")
		return nil
	}

	if !opts.Force {
		fmt.Println("This will:")
		fmt.Println("  - Stop the running service")
		fmt.Println("  - Remove the service configuration")
		fmt.Println("  - Leave configuration files and data intact")
		fmt.Println()

		if !confirm("Proceed with uninstallation?") {
			fmt.Println("Uninstallation cancelled.")
			return nil
		}
	}

	fmt.Println("\nUninstalling...")
	if err := installer.Uninstall(cfg); err != nil {
		return fmt.Errorf("uninstallation failed: %w", err)
	}

	fmt.Println("\nUninstallation complete!")
	fmt.Println("\nNote: Configuration and data files were preserved at:")
	fmt.Printf("  Config: %s\n", cfg.ConfigPath)
	fmt.Printf("  Data:   %s\n", cfg.DataPath)
	fmt.Println("You can remove these manually if no longer needed.")

	return nil
}

func RunStatus(opts CLIOptions) error {
	detection := Detect()
	printDetectionResult(detection)

	if detection.Environment == EnvDocker || detection.Environment == EnvKubernetes {
		fmt.Println("\nFor container status, use your container orchestrator's tools.")
		return nil
	}

	installer, err := GetInstaller(detection.Environment)
	if err != nil {
		fmt.Println("\nNo service installer available for this environment.")
		return nil
	}

	cfg := DefaultInstallConfig()
	status, err := installer.Status(cfg)
	if err != nil {
		return fmt.Errorf("failed to check status: %w", err)
	}

	fmt.Println("\nService Status:")
	fmt.Printf("  Installed: %v\n", status.Installed)
	fmt.Printf("  Enabled:   %v\n", status.Enabled)
	fmt.Printf("  Running:   %v\n", status.Running)
	if status.PID > 0 {
		fmt.Printf("  PID:       %d\n", status.PID)
	}
	if status.Message != "" {
		fmt.Printf("  Message:   %s\n", status.Message)
	}

	return nil
}

func printDetectionResult(d DetectionResult) {
	fmt.Println("Environment Detection:")
	fmt.Printf("  Detected:    %s\n", d.Environment.DisplayName())
	fmt.Printf("  OS:          %s/%s\n", d.OS, d.Arch)
	fmt.Printf("  Hostname:    %s\n", d.Hostname)
	fmt.Printf("  Container:   %v\n", d.IsContainer)
	fmt.Printf("  Root/Admin:  %v\n", d.IsRoot)
	if d.InitSystem != "" {
		fmt.Printf("  Init System: %s\n", d.InitSystem)
	}
}

func printManualInstructions(d DetectionResult) {
	fmt.Println("\nManual Installation Instructions:")
	fmt.Println("---------------------------------")

	switch d.Environment {
	case EnvDocker:
		fmt.Println(`
Use Docker Compose:
  1. cd odinforge-agent/deploy/docker
  2. cp .env.example .env
  3. Edit .env with your server URL and API key
  4. docker-compose up -d`)

	case EnvKubernetes:
		fmt.Println(`
Use kubectl:
  1. cd odinforge-agent/deploy/kubernetes
  2. Edit secret.yaml with your API key
  3. Edit configmap.yaml with your server URL
  4. kubectl apply -f namespace.yaml
  5. kubectl apply -f secret.yaml
  6. kubectl apply -f configmap.yaml
  7. kubectl apply -f daemonset.yaml  # or deployment.yaml`)

	case EnvSystemd:
		if !d.IsRoot {
			fmt.Println(`
Run the installer with sudo:
  sudo ./odinforge-agent install --server-url https://your-server.com --api-key YOUR_KEY`)
		}

	case EnvLaunchd:
		if !d.IsRoot {
			fmt.Println(`
Run the installer with sudo:
  sudo ./odinforge-agent install --server-url https://your-server.com --api-key YOUR_KEY`)
		}

	case EnvWindows:
		fmt.Println(`
Run as Administrator:
  1. Open PowerShell as Administrator
  2. .\odinforge-agent.exe install --server-url https://your-server.com --api-key YOUR_KEY`)

	default:
		fmt.Println(`
Manual setup required:
  1. Copy the binary to a suitable location
  2. Create a configuration file (see deploy/config.yaml.example)
  3. Set up a service or run manually`)
	}
}

func printServiceCommands(env Environment) {
	switch env {
	case EnvSystemd:
		fmt.Println("  View logs:      journalctl -u odinforge-agent -f")
		fmt.Println("  Check status:   systemctl status odinforge-agent")
		fmt.Println("  Restart:        systemctl restart odinforge-agent")
		fmt.Println("  Stop:           systemctl stop odinforge-agent")

	case EnvLaunchd:
		fmt.Println("  View logs:      tail -f /var/log/odinforge-agent/agent.log")
		fmt.Println("  Check status:   launchctl list | grep odinforge")
		fmt.Println("  Restart:        launchctl stop com.odinforge.agent && launchctl start com.odinforge.agent")
		fmt.Println("  Stop:           launchctl stop com.odinforge.agent")

	case EnvWindows:
		fmt.Println("  Check status:   sc.exe query odinforge-agent")
		fmt.Println("  Restart:        sc.exe stop odinforge-agent && sc.exe start odinforge-agent")
		fmt.Println("  Stop:           sc.exe stop odinforge-agent")
		fmt.Println("  View logs:      Get-EventLog -LogName Application -Source odinforge-agent")
	}
}

func promptForConfig(cfg *InstallConfig) error {
	reader := bufio.NewReader(os.Stdin)

	if cfg.ServerURL == "" {
		fmt.Print("\nOdinForge Server URL: ")
		url, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		cfg.ServerURL = strings.TrimSpace(url)
	}

	if cfg.APIKey == "" {
		fmt.Print("API Key (from Agents page): ")
		key, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		cfg.APIKey = strings.TrimSpace(key)
	}

	if cfg.TenantID == "" || cfg.TenantID == "default" {
		fmt.Print("Tenant ID [default]: ")
		tenant, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		tenant = strings.TrimSpace(tenant)
		if tenant != "" {
			cfg.TenantID = tenant
		}
	}

	return nil
}

func confirm(prompt string) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("%s [y/N]: ", prompt)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}
