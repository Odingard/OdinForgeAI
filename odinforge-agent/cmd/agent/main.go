package main

import (
        "context"
        "flag"
        "fmt"
        "log"
        "os"
        "os/signal"
        "syscall"
        "time"

        "odinforge-agent/internal/collector"
        "odinforge-agent/internal/config"
        "odinforge-agent/internal/installer"
        "odinforge-agent/internal/queue"
        "odinforge-agent/internal/registrar"
        "odinforge-agent/internal/sender"
)

const version = "1.0.2"

func main() {
        if len(os.Args) < 2 {
                runAgent()
                return
        }

        switch os.Args[1] {
        case "install":
                runInstallCommand()
        case "uninstall":
                runUninstallCommand()
        case "status":
                runStatusCommand()
        case "version", "--version", "-v":
                fmt.Printf("odinforge-agent version %s\n", version)
        case "help", "--help", "-h":
                printHelp()
        default:
                // Check if it starts with a dash (flag), then run agent
                if len(os.Args[1]) > 0 && os.Args[1][0] == '-' {
                        runAgent()
                } else {
                        fmt.Printf("Unknown command: %s\n", os.Args[1])
                        printHelp()
                        os.Exit(1)
                }
        }
}

func printHelp() {
        fmt.Println(`OdinForge Security Agent

Usage:
  odinforge-agent [command] [options]

Commands:
  install     Install the agent as a system service
  uninstall   Remove the agent service
  status      Show installation and service status
  version     Print version information
  help        Show this help message

Agent Options:
  --config    Path to YAML configuration file
  --once      Run once (collect + send) then exit

Install Options:
  --server-url          OdinForge server URL (required)
  --api-key             API key from OdinForge Agents page (optional if using auto-registration)
  --registration-token  Token for auto-registration (optional, alternative to api-key)
  --tenant-id           Tenant/Organization ID (default: "default")
  --force               Skip confirmation prompts
  --dry-run             Show what would be done without making changes

Examples:
  # Run agent with config file
  odinforge-agent --config /etc/odinforge/agent.yaml

  # Install as service (interactive)
  sudo odinforge-agent install

  # Install with API key (traditional)
  sudo odinforge-agent install --server-url https://odinforge.example.com --api-key YOUR_KEY

  # Install with auto-registration token (no pre-registration needed)
  sudo odinforge-agent install --server-url https://odinforge.example.com --registration-token YOUR_TOKEN

  # Check installation status
  odinforge-agent status

  # Uninstall service
  sudo odinforge-agent uninstall
`)
}

func runInstallCommand() {
        fs := flag.NewFlagSet("install", flag.ExitOnError)
        serverURL := fs.String("server-url", "", "OdinForge server URL")
        apiKey := fs.String("api-key", "", "API key from OdinForge Agents page")
        registrationToken := fs.String("registration-token", "", "Token for auto-registration")
        tenantID := fs.String("tenant-id", "default", "Tenant/Organization ID")
        force := fs.Bool("force", false, "Skip confirmation prompts")
        dryRun := fs.Bool("dry-run", false, "Show what would be done")
        fs.Parse(os.Args[2:])

        opts := installer.CLIOptions{
                ServerURL:         *serverURL,
                APIKey:            *apiKey,
                RegistrationToken: *registrationToken,
                TenantID:          *tenantID,
                Force:             *force,
                DryRun:            *dryRun,
                Interactive:       *serverURL == "" || (*apiKey == "" && *registrationToken == ""),
        }

        if err := installer.RunInstall(opts); err != nil {
                fmt.Fprintf(os.Stderr, "Error: %v\n", err)
                os.Exit(1)
        }
}

func runUninstallCommand() {
        fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
        force := fs.Bool("force", false, "Skip confirmation prompts")
        fs.Parse(os.Args[2:])

        opts := installer.CLIOptions{
                Force: *force,
        }

        if err := installer.RunUninstall(opts); err != nil {
                fmt.Fprintf(os.Stderr, "Error: %v\n", err)
                os.Exit(1)
        }
}

func runStatusCommand() {
        fs := flag.NewFlagSet("status", flag.ExitOnError)
        fs.Parse(os.Args[2:])

        opts := installer.CLIOptions{}

        if err := installer.RunStatus(opts); err != nil {
                fmt.Fprintf(os.Stderr, "Error: %v\n", err)
                os.Exit(1)
        }
}

func runAgent() {
        var (
                cfgPath = flag.String("config", "", "Path to agent YAML config (optional)")
                once    = flag.Bool("once", false, "Run once (collect + send) then exit")
        )
        flag.Parse()

        cfg, err := config.Load(*cfgPath)
        if err != nil {
                log.Fatalf("config load failed: %v", err)
        }

        // Basic safety guard: require HTTPS unless explicitly allowed.
        if cfg.Safety.RequireHTTPS && !config.IsHTTPS(cfg.Server.URL) && !config.IsLocalhost(cfg.Server.URL) {
                log.Fatalf("refusing to run: server url must be https (got %s)", cfg.Server.URL)
        }

        // Auto-registration: if no API key, try to auto-register using registration token
        if err := registrar.EnsureAPIKey(&cfg); err != nil {
                log.Fatalf("authentication setup failed: %v", err)
        }

        q, err := queue.NewBoltQueue(cfg.Buffer.Path, cfg.Buffer.MaxEvents)
        if err != nil {
                log.Fatalf("queue init failed: %v", err)
        }
        defer q.Close()

        c := collector.New(cfg)
        s, err := sender.New(cfg)
        if err != nil {
                log.Fatalf("sender init failed: %v", err)
        }

        ctx, cancel := context.WithCancel(context.Background())
        defer cancel()

        // Graceful shutdown
        sigCh := make(chan os.Signal, 2)
        signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
        go func() {
                <-sigCh
                log.Printf("shutdown signal received")
                cancel()
        }()

        // If once, do a single run.
        if *once {
                if err := runOnce(ctx, c, q, s); err != nil {
                        log.Fatalf("run-once failed: %v", err)
                }
                return
        }

        // Schedulers (with jitter)
        telemetryTicker := time.NewTicker(cfg.Collection.TelemetryInterval)
        heartbeatTicker := time.NewTicker(cfg.Collection.HeartbeatInterval)
        flushTicker := time.NewTicker(5 * time.Second)
        defer telemetryTicker.Stop()
        defer heartbeatTicker.Stop()
        defer flushTicker.Stop()

        log.Printf("odinforge-agent started | server=%s | tenant=%s", cfg.Server.URL, cfg.Auth.TenantID)

        // initial telemetry
        enqueueTelemetry(ctx, c, q)

        for {
                select {
                case <-ctx.Done():
                        log.Printf("exiting main loop")
                        return
                case <-heartbeatTicker.C:
                        enqueueHeartbeat(c, q)
                case <-telemetryTicker.C:
                        enqueueTelemetry(ctx, c, q)
                case <-flushTicker.C:
                        // drain queue in the background cadence
                        if err := s.Flush(ctx, q); err != nil {
                                log.Printf("flush error: %v", err)
                        }
                }
        }
}

func runOnce(ctx context.Context, c *collector.Collector, q *queue.BoltQueue, s *sender.Sender) error {
        enqueueTelemetry(ctx, c, q)
        enqueueHeartbeat(c, q)
        if err := s.Flush(ctx, q); err != nil {
                return err
        }
        log.Printf("run-once completed successfully")
        return nil
}

func enqueueTelemetry(ctx context.Context, c *collector.Collector, q *queue.BoltQueue) {
        ev, err := c.CollectTelemetry(ctx)
        if err != nil {
                log.Printf("telemetry collection failed: %v", err)
                return
        }
        if err := q.Enqueue(ev); err != nil {
                log.Printf("queue enqueue failed: %v", err)
        }
}

func enqueueHeartbeat(c *collector.Collector, q *queue.BoltQueue) {
        ev := c.HeartbeatEvent()
        if err := q.Enqueue(ev); err != nil {
                log.Printf("heartbeat enqueue failed: %v", err)
        }
}
