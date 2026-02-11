package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"odinforge-agent/internal/collector"
	"odinforge-agent/internal/config"
	"odinforge-agent/internal/healthz"
	"odinforge-agent/internal/installer"
	"odinforge-agent/internal/logger"
	"odinforge-agent/internal/prober"
	"odinforge-agent/internal/queue"
	"odinforge-agent/internal/registrar"
	"odinforge-agent/internal/sender"
	"odinforge-agent/internal/service"
	"odinforge-agent/internal/updater"
	"odinforge-agent/internal/watchdog"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "1.0.4-dev"

var log = logger.WithComponent("main")

func main() {
	logger.Init(logger.INFO)

	// Check if running as Windows service
	if service.IsWindowsService() {
		log.Info("detected Windows service mode")
		if err := service.RunAsService("odinforge-agent", runAgentWithContext); err != nil {
			log.Error("failed to run as Windows service", "error", err.Error())
			os.Exit(1)
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
		log.Error("config load failed", "error", err.Error())
		os.Exit(1)
	}

	if cfg.Safety.RequireHTTPS && !config.IsHTTPS(cfg.Server.URL) && !config.IsLocalhost(cfg.Server.URL) {
		log.Error("refusing to run: server url must be https", "url", cfg.Server.URL)
		os.Exit(1)
	}

	q, err := queue.NewBoltQueue(cfg.Buffer.Path, cfg.Buffer.MaxEvents)
	if err != nil {
		log.Error("queue init failed", "error", err.Error())
		os.Exit(1)
	}
	defer q.Close()

	stats := watchdog.NewStats()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown with timeout
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Info("shutdown signal received, draining...")
		cancel()
		// Force exit after 30s if graceful shutdown stalls
		time.AfterFunc(30*time.Second, func() {
			log.Error("graceful shutdown timed out, forcing exit")
			os.Exit(1)
		})
	}()

	// Start health endpoint
	if cfg.Health.Enabled {
		hz := healthz.New(stats, cfg.Health.Port)
		go hz.Run(ctx)
	}

	// Start watchdog monitoring
	go watchdog.Run(ctx, stats)

	// Start auto-updater
	if cfg.Update.Enabled {
		u := updater.New(cfg, version)
		go u.Run(ctx)
	}

	log.Info("odinforge-agent starting",
		"version", version,
		"server", cfg.Server.URL,
		"tenant", cfg.Auth.TenantID,
	)

	// Channel to signal when authentication is ready
	authReady := make(chan bool, 1)
	var authError error

	// Run authentication in background to avoid Windows service timeout (error 1053)
	go func() {
		if err := registrar.EnsureAPIKey(&cfg); err != nil {
			authError = err
			log.Warn("authentication setup failed (will retry)", "error", err.Error())
			authReady <- false
			return
		}
		log.Info("authentication setup complete")
		authReady <- true
	}()

	// If once, wait for auth then do a single run
	if *once {
		<-authReady
		if authError != nil {
			log.Error("authentication setup failed", "error", authError.Error())
			os.Exit(1)
		}
		c := collector.New(cfg)
		s, err := sender.New(cfg)
		if err != nil {
			log.Error("sender init failed", "error", err.Error())
			os.Exit(1)
		}
		if err := runOnce(ctx, c, q, s, stats); err != nil {
			log.Error("run-once failed", "error", err.Error())
			os.Exit(1)
		}
		return
	}

	// For service mode, continue immediately (don't block on auth)
	// This prevents Windows error 1053 (service timeout)

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
			log.Info("exiting main loop")
			return

		case ready := <-authReady:
			if ready && !authenticated {
				authenticated = true
				c = collector.New(cfg)
				s, err = sender.New(cfg)
				if err != nil {
					log.Error("sender init failed", "error", err.Error())
					authenticated = false
					continue
				}
				log.Info("odinforge-agent fully started",
					"server", cfg.Server.URL,
					"tenant", cfg.Auth.TenantID,
				)
				enqueueTelemetry(ctx, c, q, stats)
			}

		case <-authRetryTicker.C:
			if !authenticated && authError != nil {
				log.Info("retrying authentication")
				authError = nil
				go func() {
					if err := registrar.EnsureAPIKey(&cfg); err != nil {
						authError = err
						log.Warn("authentication retry failed", "error", err.Error())
						authReady <- false
						return
					}
					authReady <- true
				}()
			}

		case <-heartbeatTicker.C:
			if authenticated && c != nil {
				enqueueHeartbeat(c, q, stats)
			}

		case <-telemetryTicker.C:
			if authenticated && c != nil {
				enqueueTelemetry(ctx, c, q, stats)
			}

		case <-commandPollTicker.C:
			if authenticated && s != nil {
				pollAndExecuteCommands(ctx, cfg, c, q, s, stats)
			}

		case <-flushTicker.C:
			if authenticated && s != nil {
				if err := s.Flush(ctx, q); err != nil {
					stats.FlushErrors.Add(1)
					log.Error("flush error", "error", err.Error())
				} else {
					stats.LastFlushAt.Store(time.Now().Unix())
					if d, err := q.Depth(); err == nil {
						stats.QueueDepth.Store(int64(d))
					}
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
		log.Error("config load failed", "error", err.Error())
		return
	}

	if cfg.Safety.RequireHTTPS && !config.IsHTTPS(cfg.Server.URL) && !config.IsLocalhost(cfg.Server.URL) {
		log.Error("refusing to run: server url must be https", "url", cfg.Server.URL)
		return
	}

	q, err := queue.NewBoltQueue(cfg.Buffer.Path, cfg.Buffer.MaxEvents)
	if err != nil {
		log.Error("queue init failed", "error", err.Error())
		return
	}
	defer q.Close()

	stats := watchdog.NewStats()

	// Start health endpoint
	if cfg.Health.Enabled {
		hz := healthz.New(stats, cfg.Health.Port)
		go hz.Run(ctx)
	}

	// Start watchdog monitoring
	go watchdog.Run(ctx, stats)

	// Start auto-updater
	if cfg.Update.Enabled {
		u := updater.New(cfg, version)
		go u.Run(ctx)
	}

	log.Info("odinforge-agent starting (Windows service)",
		"version", version,
		"server", cfg.Server.URL,
		"tenant", cfg.Auth.TenantID,
	)

	// Channel to signal when authentication is ready
	authReady := make(chan bool, 1)
	var authError error

	// Run authentication in background
	go func() {
		if err := registrar.EnsureAPIKey(&cfg); err != nil {
			authError = err
			log.Warn("authentication setup failed (will retry)", "error", err.Error())
			authReady <- false
			return
		}
		log.Info("authentication setup complete")
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
			log.Info("exiting main loop (Windows service stop)")
			return

		case ready := <-authReady:
			if ready && !authenticated {
				authenticated = true
				c = collector.New(cfg)
				s, err = sender.New(cfg)
				if err != nil {
					log.Error("sender init failed", "error", err.Error())
					authenticated = false
					continue
				}
				log.Info("odinforge-agent fully started",
					"server", cfg.Server.URL,
					"tenant", cfg.Auth.TenantID,
				)
				enqueueTelemetry(ctx, c, q, stats)
			}

		case <-authRetryTicker.C:
			if !authenticated && authError != nil {
				log.Info("retrying authentication")
				authError = nil
				go func() {
					if err := registrar.EnsureAPIKey(&cfg); err != nil {
						authError = err
						log.Warn("authentication retry failed", "error", err.Error())
						authReady <- false
						return
					}
					authReady <- true
				}()
			}

		case <-heartbeatTicker.C:
			if authenticated && c != nil {
				enqueueHeartbeat(c, q, stats)
			}

		case <-telemetryTicker.C:
			if authenticated && c != nil {
				enqueueTelemetry(ctx, c, q, stats)
			}

		case <-commandPollTicker.C:
			if authenticated && s != nil {
				pollAndExecuteCommands(ctx, cfg, c, q, s, stats)
			}

		case <-flushTicker.C:
			if authenticated && s != nil {
				if err := s.Flush(ctx, q); err != nil {
					stats.FlushErrors.Add(1)
					log.Error("flush error", "error", err.Error())
				} else {
					stats.LastFlushAt.Store(time.Now().Unix())
					if d, err := q.Depth(); err == nil {
						stats.QueueDepth.Store(int64(d))
					}
				}
			}
		}
	}
}

func runOnce(ctx context.Context, c *collector.Collector, q *queue.BoltQueue, s *sender.Sender, stats *watchdog.Stats) error {
	enqueueTelemetry(ctx, c, q, stats)
	enqueueHeartbeat(c, q, stats)
	if err := s.Flush(ctx, q); err != nil {
		return err
	}
	log.Info("run-once completed successfully")
	return nil
}

func enqueueTelemetry(ctx context.Context, c *collector.Collector, q *queue.BoltQueue, stats *watchdog.Stats) {
	ev, err := c.CollectTelemetry(ctx)
	if err != nil {
		log.Error("telemetry collection failed", "error", err.Error())
		return
	}
	if err := q.Enqueue(ev); err != nil {
		log.Error("queue enqueue failed", "error", err.Error())
		return
	}
	stats.TelemetrySent.Add(1)
	stats.LastTelemetryAt.Store(time.Now().Unix())
}

func enqueueHeartbeat(c *collector.Collector, q *queue.BoltQueue, stats *watchdog.Stats) {
	ev := c.HeartbeatEvent()
	if err := q.Enqueue(ev); err != nil {
		log.Error("heartbeat enqueue failed", "error", err.Error())
		return
	}
	stats.HeartbeatsSent.Add(1)
	stats.LastHeartbeatAt.Store(time.Now().Unix())
}

func pollAndExecuteCommands(ctx context.Context, cfg config.Config, c *collector.Collector, q *queue.BoltQueue, s *sender.Sender, stats *watchdog.Stats) {
	agentID := cfg.Auth.TenantID
	if cfg.Auth.APIKey != "" {
		if len(cfg.Auth.APIKey) >= 8 {
			agentID = "agent-" + cfg.Auth.APIKey[:8]
		}
	}

	commands, err := s.PollCommands(ctx, agentID)
	if err != nil {
		log.Error("command poll error", "error", err.Error())
		return
	}

	if len(commands) == 0 {
		return
	}

	log.Info("received commands from server", "count", len(commands))

	for _, cmd := range commands {
		executeCommand(ctx, cfg, c, q, s, agentID, cmd, stats)
	}
}

func executeCommand(ctx context.Context, cfg config.Config, c *collector.Collector, q *queue.BoltQueue, s *sender.Sender, agentID string, cmd sender.Command, stats *watchdog.Stats) {
	log.Info("executing command", "id", cmd.ID, "type", cmd.CommandType)

	var result map[string]interface{}
	var errorMsg string

	switch cmd.CommandType {
	case "force_checkin":
		enqueueTelemetry(ctx, c, q, stats)
		enqueueHeartbeat(c, q, stats)
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
		enqueueTelemetry(ctx, c, q, stats)
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

	if err := s.CompleteCommand(ctx, agentID, cmd.ID, result, errorMsg); err != nil {
		log.Error("failed to report command completion", "id", cmd.ID, "error", err.Error())
	} else {
		stats.CommandsExec.Add(1)
		log.Info("command completed", "id", cmd.ID)
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

	log.Info("running validation probes", "host", host, "probes", probes)

	var allResults []prober.ProbeResult

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
