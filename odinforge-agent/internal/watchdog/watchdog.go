package watchdog

import (
	"context"
	"runtime"
	"sync/atomic"
	"time"

	"odinforge-agent/internal/logger"
)

var log = logger.WithComponent("watchdog")

// Stats tracks agent health metrics
type Stats struct {
	TelemetrySent   atomic.Int64
	HeartbeatsSent  atomic.Int64
	FlushErrors     atomic.Int64
	CommandsExec    atomic.Int64
	QueueDepth      atomic.Int64
	LastTelemetryAt atomic.Int64 // unix timestamp
	LastHeartbeatAt atomic.Int64 // unix timestamp
	LastFlushAt     atomic.Int64 // unix timestamp
	Uptime          time.Time
}

// NewStats creates a new stats tracker
func NewStats() *Stats {
	return &Stats{Uptime: time.Now()}
}

// HealthStatus represents the agent's health
type HealthStatus struct {
	Healthy            bool    `json:"healthy"`
	Uptime             string  `json:"uptime"`
	TelemetrySent      int64   `json:"telemetrySent"`
	HeartbeatsSent     int64   `json:"heartbeatsSent"`
	FlushErrors        int64   `json:"flushErrors"`
	CommandsExecuted   int64   `json:"commandsExecuted"`
	QueueDepth         int64   `json:"queueDepth"`
	LastTelemetry      string  `json:"lastTelemetry,omitempty"`
	LastHeartbeat      string  `json:"lastHeartbeat,omitempty"`
	MemoryAllocMB      float64 `json:"memoryAllocMB"`
	NumGoroutines      int     `json:"numGoroutines"`
}

// Status returns current health status
func (s *Stats) Status() HealthStatus {
	var lastTelemetry, lastHeartbeat string
	if ts := s.LastTelemetryAt.Load(); ts > 0 {
		lastTelemetry = time.Unix(ts, 0).UTC().Format(time.RFC3339)
	}
	if ts := s.LastHeartbeatAt.Load(); ts > 0 {
		lastHeartbeat = time.Unix(ts, 0).UTC().Format(time.RFC3339)
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return HealthStatus{
		Healthy:          s.isHealthy(),
		Uptime:           time.Since(s.Uptime).Round(time.Second).String(),
		TelemetrySent:    s.TelemetrySent.Load(),
		HeartbeatsSent:   s.HeartbeatsSent.Load(),
		FlushErrors:      s.FlushErrors.Load(),
		CommandsExecuted: s.CommandsExec.Load(),
		QueueDepth:       s.QueueDepth.Load(),
		LastTelemetry:    lastTelemetry,
		LastHeartbeat:    lastHeartbeat,
		MemoryAllocMB:    float64(memStats.Alloc) / 1024 / 1024,
		NumGoroutines:    runtime.NumGoroutine(),
	}
}

func (s *Stats) isHealthy() bool {
	// Unhealthy if no telemetry sent in 15 minutes (3x the 5-min interval)
	if ts := s.LastTelemetryAt.Load(); ts > 0 {
		if time.Since(time.Unix(ts, 0)) > 15*time.Minute {
			return false
		}
	}
	// Unhealthy if flush errors exceed 50
	if s.FlushErrors.Load() > 50 {
		return false
	}
	return true
}

// Run starts the watchdog monitoring loop
func Run(ctx context.Context, stats *Stats) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			status := stats.Status()
			if !status.Healthy {
				log.Warn("agent health degraded",
					"uptime", status.Uptime,
					"flush_errors", status.FlushErrors,
					"queue_depth", status.QueueDepth,
					"memory_mb", status.MemoryAllocMB,
					"goroutines", status.NumGoroutines,
				)
			} else {
				log.Debug("health check ok",
					"uptime", status.Uptime,
					"telemetry_sent", status.TelemetrySent,
					"queue_depth", status.QueueDepth,
					"memory_mb", status.MemoryAllocMB,
				)
			}
		}
	}
}
