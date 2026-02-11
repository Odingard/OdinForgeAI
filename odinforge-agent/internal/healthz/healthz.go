package healthz

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"odinforge-agent/internal/logger"
	"odinforge-agent/internal/watchdog"
)

var log = logger.WithComponent("healthz")

// Server provides health check endpoints
type Server struct {
	stats *watchdog.Stats
	addr  string
}

// New creates a health check server
func New(stats *watchdog.Stats, port string) *Server {
	if port == "" {
		port = "9090"
	}
	return &Server{
		stats: stats,
		addr:  "127.0.0.1:" + port,
	}
}

// Run starts the health check HTTP server
func (s *Server) Run(ctx context.Context) {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		status := s.stats.Status()
		w.Header().Set("Content-Type", "application/json")
		if !status.Healthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(status)
	})

	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		status := s.stats.Status()
		if status.TelemetrySent > 0 {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"ready":true}`))
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"ready":false}`))
		}
	})

	srv := &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()

	log.Info("health endpoint listening", "addr", s.addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Error("health server error", "error", err.Error())
	}
}
