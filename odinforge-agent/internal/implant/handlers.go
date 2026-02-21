package implant

import (
	"context"
	"time"

	"odinforge-agent/internal/collector"
	"odinforge-agent/internal/prober"
	"odinforge-agent/internal/queue"
	"odinforge-agent/internal/sender"
	"odinforge-agent/internal/watchdog"
)

// ---------------------------------------------------------------------------
// CheckinHandler — handles "force_checkin" commands
// ---------------------------------------------------------------------------

type CheckinHandler struct {
	collector *collector.Collector
	queue     *queue.BoltQueue
	sender    *sender.Sender
	stats     *watchdog.Stats
}

func NewCheckinHandler(c *collector.Collector, q *queue.BoltQueue, s *sender.Sender, stats *watchdog.Stats) *CheckinHandler {
	return &CheckinHandler{collector: c, queue: q, sender: s, stats: stats}
}

func (h *CheckinHandler) Name() string { return "checkin" }

func (h *CheckinHandler) Handle(ctx context.Context, _ map[string]interface{}) (Result, error) {
	// Collect and enqueue telemetry
	ev, err := h.collector.CollectTelemetry(ctx)
	if err != nil {
		log.Error("telemetry collection failed during checkin", "error", err.Error())
	} else {
		if err := h.queue.Enqueue(ev); err != nil {
			log.Error("telemetry enqueue failed", "error", err.Error())
		} else {
			h.stats.TelemetrySent.Add(1)
			h.stats.LastTelemetryAt.Store(time.Now().Unix())
		}
	}

	// Enqueue heartbeat
	hbEv := h.collector.HeartbeatEvent()
	if err := h.queue.Enqueue(hbEv); err != nil {
		log.Error("heartbeat enqueue failed", "error", err.Error())
	} else {
		h.stats.HeartbeatsSent.Add(1)
		h.stats.LastHeartbeatAt.Store(time.Now().Unix())
	}

	// Flush queue to server
	if err := h.sender.Flush(ctx, h.queue); err != nil {
		return Result{}, err
	}

	return Result{
		Status: "completed",
		Data: map[string]interface{}{
			"executedAt":    time.Now().Format(time.RFC3339),
			"telemetrySent": true,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// ScanHandler — handles "run_scan" commands
// ---------------------------------------------------------------------------

type ScanHandler struct {
	collector *collector.Collector
	queue     *queue.BoltQueue
	stats     *watchdog.Stats
}

func NewScanHandler(c *collector.Collector, q *queue.BoltQueue, stats *watchdog.Stats) *ScanHandler {
	return &ScanHandler{collector: c, queue: q, stats: stats}
}

func (h *ScanHandler) Name() string { return "scanner" }

func (h *ScanHandler) Handle(ctx context.Context, _ map[string]interface{}) (Result, error) {
	ev, err := h.collector.CollectTelemetry(ctx)
	if err != nil {
		log.Error("telemetry collection failed during scan", "error", err.Error())
	} else {
		if err := h.queue.Enqueue(ev); err != nil {
			log.Error("telemetry enqueue failed", "error", err.Error())
		} else {
			h.stats.TelemetrySent.Add(1)
			h.stats.LastTelemetryAt.Store(time.Now().Unix())
		}
	}

	return Result{
		Status: "completed",
		Data: map[string]interface{}{
			"executedAt": time.Now().Format(time.RFC3339),
			"scanType":   "full",
		},
	}, nil
}

// ---------------------------------------------------------------------------
// ProbeHandler — handles "validation_probe" commands
// ---------------------------------------------------------------------------

type ProbeHandler struct{}

func NewProbeHandler() *ProbeHandler {
	return &ProbeHandler{}
}

func (h *ProbeHandler) Name() string { return "prober" }

func (h *ProbeHandler) Handle(ctx context.Context, payload map[string]interface{}) (Result, error) {
	host, _ := payload["host"].(string)
	if host == "" {
		return Result{
			Status: "error",
			Error:  "missing required 'host' parameter",
		}, nil
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

	return Result{
		Status: "completed",
		Data: map[string]interface{}{
			"executedAt":       time.Now().Format(time.RFC3339),
			"host":             host,
			"probeCount":       len(allResults),
			"vulnerableCount":  vulnerableCount,
			"criticalFindings": criticalFindings,
			"results":          allResults,
		},
	}, nil
}
