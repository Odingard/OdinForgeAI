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
        "odinforge-agent/internal/prober"
        "odinforge-agent/internal/queue"
        "odinforge-agent/internal/registrar"
        "odinforge-agent/internal/sender"
        "odinforge-agent/internal/service"
)

const version = "1.0.3"

func main() {
        // Check if running as Windows service
        if service.IsWindowsService() {
                log.Printf("Detected Windows service mode")
                if err := service.RunAsService("odinforge-agent", runAgentWithContext); err != nil {
                        log.Fatalf("Failed to run as Windows service: %v", err)
                }
                return
        }

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
  sudo odinforge-agent uninstall`)
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

        // Create queue early so we can start the service loop
        q, err := queue.NewBoltQueue(cfg.Buffer.Path, cfg.Buffer.MaxEvents)
        if err != nil {
                log.Fatalf("queue init failed: %v", err)
        }
        defer q.Close()

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

        log.Printf("odinforge-agent starting | server=%s | tenant=%s", cfg.Server.URL, cfg.Auth.TenantID)

        // Channel to signal when authentication is ready
        authReady := make(chan bool, 1)
        var authError error

        // Run authentication in background to avoid Windows service timeout (error 1053)
        go func() {
                if err := registrar.EnsureAPIKey(&cfg); err != nil {
                        authError = err
                        log.Printf("authentication setup failed (will retry): %v", err)
                        authReady <- false
                        return
                }
                log.Printf("authentication setup complete")
                authReady <- true
        }()

        // If once, wait for auth then do a single run
        if *once {
                <-authReady
                if authError != nil {
                        log.Fatalf("authentication setup failed: %v", authError)
                }
                c := collector.New(cfg)
                s, err := sender.New(cfg)
                if err != nil {
                        log.Fatalf("sender init failed: %v", err)
                }
                if err := runOnce(ctx, c, q, s); err != nil {
                        log.Fatalf("run-once failed: %v", err)
                }
                return
        }

        // For service mode, continue immediately (don't block on auth)
        // This prevents Windows error 1053 (service timeout)

        // Schedulers (with jitter)
        telemetryTicker := time.NewTicker(cfg.Collection.TelemetryInterval)
        heartbeatTicker := time.NewTicker(cfg.Collection.HeartbeatInterval)
        commandPollTicker := time.NewTicker(30 * time.Second)
        flushTicker := time.NewTicker(5 * time.Second)
        authRetryTicker := time.NewTicker(10 * time.Second)
        defer telemetryTicker.Stop()
        defer heartbeatTicker.Stop()
        defer commandPollTicker.Stop()
        defer flushTicker.Stop()
        defer authRetryTicker.Stop()

        var c *collector.Collector
        var s *sender.Sender
        authenticated := false

        for {
                select {
                case <-ctx.Done():
                        log.Printf("exiting main loop")
                        return

                case ready := <-authReady:
                        if ready && !authenticated {
                                authenticated = true
                                c = collector.New(cfg)
                                s, err = sender.New(cfg)
                                if err != nil {
                                        log.Printf("sender init failed: %v", err)
                                        authenticated = false
                                        continue
                                }
                                log.Printf("odinforge-agent fully started | server=%s | tenant=%s", cfg.Server.URL, cfg.Auth.TenantID)
                                enqueueTelemetry(ctx, c, q)
                        }

                case <-authRetryTicker.C:
                        if !authenticated && authError != nil {
                                log.Printf("retrying authentication...")
                                authError = nil
                                go func() {
                                        if err := registrar.EnsureAPIKey(&cfg); err != nil {
                                                authError = err
                                                log.Printf("authentication retry failed: %v", err)
                                                authReady <- false
                                                return
                                        }
                                        authReady <- true
                                }()
                        }

                case <-heartbeatTicker.C:
                        if authenticated && c != nil {
                                enqueueHeartbeat(c, q)
                        }

                case <-telemetryTicker.C:
                        if authenticated && c != nil {
                                enqueueTelemetry(ctx, c, q)
                        }

                case <-commandPollTicker.C:
                        if authenticated && s != nil {
                                pollAndExecuteCommands(ctx, cfg, c, q, s)
                        }

                case <-flushTicker.C:
                        if authenticated && s != nil {
                                if err := s.Flush(ctx, q); err != nil {
                                        log.Printf("flush error: %v", err)
                                }
                        }
                }
        }
}

// runAgentWithContext is called when running as a Windows service
// The context is managed by the Windows service handler
func runAgentWithContext(ctx context.Context) {
        cfg, err := config.Load("")
        if err != nil {
                log.Printf("config load failed: %v", err)
                return
        }

        // Basic safety guard: require HTTPS unless explicitly allowed.
        if cfg.Safety.RequireHTTPS && !config.IsHTTPS(cfg.Server.URL) && !config.IsLocalhost(cfg.Server.URL) {
                log.Printf("refusing to run: server url must be https (got %s)", cfg.Server.URL)
                return
        }

        // Create queue early so we can start the service loop
        q, err := queue.NewBoltQueue(cfg.Buffer.Path, cfg.Buffer.MaxEvents)
        if err != nil {
                log.Printf("queue init failed: %v", err)
                return
        }
        defer q.Close()

        log.Printf("odinforge-agent starting (Windows service) | server=%s | tenant=%s", cfg.Server.URL, cfg.Auth.TenantID)

        // Channel to signal when authentication is ready
        authReady := make(chan bool, 1)
        var authError error

        // Run authentication in background
        go func() {
                if err := registrar.EnsureAPIKey(&cfg); err != nil {
                        authError = err
                        log.Printf("authentication setup failed (will retry): %v", err)
                        authReady <- false
                        return
                }
                log.Printf("authentication setup complete")
                authReady <- true
        }()

        // Schedulers
        telemetryTicker := time.NewTicker(cfg.Collection.TelemetryInterval)
        heartbeatTicker := time.NewTicker(cfg.Collection.HeartbeatInterval)
        commandPollTicker := time.NewTicker(30 * time.Second)
        flushTicker := time.NewTicker(5 * time.Second)
        authRetryTicker := time.NewTicker(10 * time.Second)
        defer telemetryTicker.Stop()
        defer heartbeatTicker.Stop()
        defer commandPollTicker.Stop()
        defer flushTicker.Stop()
        defer authRetryTicker.Stop()

        var c *collector.Collector
        var s *sender.Sender
        authenticated := false

        for {
                select {
                case <-ctx.Done():
                        log.Printf("exiting main loop (Windows service stop)")
                        return

                case ready := <-authReady:
                        if ready && !authenticated {
                                authenticated = true
                                c = collector.New(cfg)
                                s, err = sender.New(cfg)
                                if err != nil {
                                        log.Printf("sender init failed: %v", err)
                                        authenticated = false
                                        continue
                                }
                                log.Printf("odinforge-agent fully started | server=%s | tenant=%s", cfg.Server.URL, cfg.Auth.TenantID)
                                enqueueTelemetry(ctx, c, q)
                        }

                case <-authRetryTicker.C:
                        if !authenticated && authError != nil {
                                log.Printf("retrying authentication...")
                                authError = nil
                                go func() {
                                        if err := registrar.EnsureAPIKey(&cfg); err != nil {
                                                authError = err
                                                log.Printf("authentication retry failed: %v", err)
                                                authReady <- false
                                                return
                                        }
                                        authReady <- true
                                }()
                        }

                case <-heartbeatTicker.C:
                        if authenticated && c != nil {
                                enqueueHeartbeat(c, q)
                        }

                case <-telemetryTicker.C:
                        if authenticated && c != nil {
                                enqueueTelemetry(ctx, c, q)
                        }

                case <-commandPollTicker.C:
                        if authenticated && s != nil {
                                pollAndExecuteCommands(ctx, cfg, c, q, s)
                        }

                case <-flushTicker.C:
                        if authenticated && s != nil {
                                if err := s.Flush(ctx, q); err != nil {
                                        log.Printf("flush error: %v", err)
                                }
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

func pollAndExecuteCommands(ctx context.Context, cfg config.Config, c *collector.Collector, q *queue.BoltQueue, s *sender.Sender) {
        // Get agent ID from config (derived from API key or stored during registration)
        agentID := cfg.Auth.TenantID // Use tenant ID as fallback
        if cfg.Auth.APIKey != "" {
                // Agent ID is typically stored alongside the API key during registration
                // For now, we use the API key prefix as agent identifier
                if len(cfg.Auth.APIKey) >= 8 {
                        agentID = "agent-" + cfg.Auth.APIKey[:8]
                }
        }

        // Poll for pending commands
        commands, err := s.PollCommands(ctx, agentID)
        if err != nil {
                log.Printf("command poll error: %v", err)
                return
        }

        if len(commands) == 0 {
                return
        }

        log.Printf("received %d commands from server", len(commands))

        // Execute each command
        for _, cmd := range commands {
                executeCommand(ctx, cfg, c, q, s, agentID, cmd)
        }
}

func executeCommand(ctx context.Context, cfg config.Config, c *collector.Collector, q *queue.BoltQueue, s *sender.Sender, agentID string, cmd sender.Command) {
        log.Printf("executing command: %s (type: %s)", cmd.ID, cmd.CommandType)

        var result map[string]interface{}
        var errorMsg string

        switch cmd.CommandType {
        case "force_checkin":
                // Immediately collect and queue telemetry
                enqueueTelemetry(ctx, c, q)
                enqueueHeartbeat(c, q)
                // Flush immediately to send data
                if err := s.Flush(ctx, q); err != nil {
                        errorMsg = err.Error()
                } else {
                        result = map[string]interface{}{
                                "status":        "completed",
                                "executedAt":    time.Now().Format(time.RFC3339),
                                "telemetrySent": true,
                        }
                }

        case "run_scan":
                // Trigger a full scan
                enqueueTelemetry(ctx, c, q)
                result = map[string]interface{}{
                        "status":     "completed",
                        "executedAt": time.Now().Format(time.RFC3339),
                        "scanType":   "full",
                }

        case "validation_probe":
                result = executeValidationProbe(ctx, cmd.Payload)

        default:
                errorMsg = "unknown command type: " + cmd.CommandType
        }

        // Report completion to server
        if err := s.CompleteCommand(ctx, agentID, cmd.ID, result, errorMsg); err != nil {
                log.Printf("failed to report command completion: %v", err)
        } else {
                log.Printf("command %s completed successfully", cmd.ID)
        }
}

func executeValidationProbe(ctx context.Context, payload map[string]interface{}) map[string]interface{} {
        start := time.Now()

        host, _ := payload["host"].(string)
        if host == "" {
                return map[string]interface{}{
                        "status": "error",
                        "error":  "missing required 'host' parameter",
                }
        }

        probeTypes, _ := payload["probes"].([]interface{})
        var probes []string
        for _, p := range probeTypes {
                if pStr, ok := p.(string); ok {
                        probes = append(probes, pStr)
                }
        }

        port := 0
        if portFloat, ok := payload["port"].(float64); ok {
                port = int(portFloat)
        }

        timeout := 5000
        if timeoutFloat, ok := payload["timeout"].(float64); ok {
                timeout = int(timeoutFloat)
        }

        log.Printf("running validation probes on %s: %v", host, probes)

        var allResults []prober.ProbeResult

        // Run protocol probes
        if len(probes) > 0 {
                cfg := prober.ProbeConfig{
                        Host:    host,
                        Port:    port,
                        Timeout: timeout,
                        Probes:  probes,
                }
                p := prober.New(cfg)
                results := p.RunProbes(ctx)
                allResults = append(allResults, results...)
        }

        // Run credential probes if requested
        credServices, _ := payload["credentialServices"].([]interface{})
        if len(credServices) > 0 {
                credProber := prober.NewCredentialProber(host, timeout)
                for _, svc := range credServices {
                        svcStr, ok := svc.(string)
                        if !ok {
                                continue
                        }
                        result := credProber.ProbeService(ctx, prober.ServiceType(svcStr), port)
                        allResults = append(allResults, result)
                }
        }

        // Aggregate findings
        var vulnerableCount int
        var criticalFindings []string
        for _, r := range allResults {
                if r.Vulnerable {
                        vulnerableCount++
                        if r.Confidence >= 90 {
                                criticalFindings = append(criticalFindings, r.Evidence)
                        }
                }
        }

        return map[string]interface{}{
                "status":           "completed",
                "executedAt":       time.Now().Format(time.RFC3339),
                "host":             host,
                "probeCount":       len(allResults),
                "vulnerableCount":  vulnerableCount,
                "criticalFindings": criticalFindings,
                "results":          allResults,
                "executionMs":      time.Since(start).Milliseconds(),
        }
}
