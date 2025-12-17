package config

import (
	"errors"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server     ServerConfig `yaml:"server"`
	Auth       AuthConfig   `yaml:"auth"`
	Collection CollectCfg   `yaml:"collection"`
	Buffer     BufferCfg    `yaml:"buffer"`
	Transport  TransCfg     `yaml:"transport"`
	Safety     SafetyCfg    `yaml:"safety"`
}

type ServerConfig struct {
	URL        string `yaml:"url"`
	VerifyTLS  bool   `yaml:"verify_tls"`
	PinnedSPKI string `yaml:"pinned_spki"` // optional: base64 SPKI pin
}

type AuthConfig struct {
	TenantID string `yaml:"tenant_id"`
	Mode     string `yaml:"mode"` // "api_key" or "mtls"
	APIKey   string `yaml:"api_key"`

	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
	CAPath   string `yaml:"ca_path"` // optional custom CA
}

type CollectCfg struct {
	TelemetryInterval time.Duration `yaml:"telemetry_interval"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
}

type BufferCfg struct {
	Path      string `yaml:"path"`
	MaxEvents int    `yaml:"max_events"`
}

type TransCfg struct {
	Timeout   time.Duration `yaml:"timeout"`
	BatchSize int           `yaml:"batch_size"`
	Compress  bool          `yaml:"compress"`
}

type SafetyCfg struct {
	RequireHTTPS bool `yaml:"require_https"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			URL:       "http://localhost:8080",
			VerifyTLS: true,
		},
		Auth: AuthConfig{
			Mode: "api_key",
		},
		Collection: CollectCfg{
			TelemetryInterval: 300 * time.Second,
			HeartbeatInterval: 60 * time.Second,
		},
		Buffer: BufferCfg{
			Path:      "./odinforge-agent.queue.db",
			MaxEvents: 50000,
		},
		Transport: TransCfg{
			Timeout:   15 * time.Second,
			BatchSize: 50,
			Compress:  true,
		},
		Safety: SafetyCfg{
			RequireHTTPS: true,
		},
	}
}

// Load merges: defaults <- yaml <- env
func Load(path string) (Config, error) {
	cfg := Default()

	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return cfg, err
		}
		if err := yaml.Unmarshal(b, &cfg); err != nil {
			return cfg, err
		}
	}

	applyEnv(&cfg)

	if cfg.Server.URL == "" {
		return cfg, errors.New("server.url is required")
	}
	if cfg.Auth.TenantID == "" {
		// allow empty for dev, but recommended
		cfg.Auth.TenantID = "default"
	}
	if cfg.Transport.BatchSize <= 0 {
		cfg.Transport.BatchSize = 50
	}
	if cfg.Buffer.MaxEvents <= 0 {
		cfg.Buffer.MaxEvents = 50000
	}

	return cfg, nil
}

func applyEnv(cfg *Config) {
	// Server
	if v := os.Getenv("ODINFORGE_SERVER_URL"); v != "" {
		cfg.Server.URL = v
	}
	if v := os.Getenv("ODINFORGE_VERIFY_TLS"); v != "" {
		cfg.Server.VerifyTLS = (v == "1" || strings.EqualFold(v, "true"))
	}
	if v := os.Getenv("ODINFORGE_PINNED_SPKI"); v != "" {
		cfg.Server.PinnedSPKI = v
	}

	// Auth
	if v := os.Getenv("ODINFORGE_TENANT_ID"); v != "" {
		cfg.Auth.TenantID = v
	}
	if v := os.Getenv("ODINFORGE_AUTH_MODE"); v != "" {
		cfg.Auth.Mode = v
	}
	if v := os.Getenv("ODINFORGE_API_KEY"); v != "" {
		cfg.Auth.APIKey = v
	}
	if v := os.Getenv("ODINFORGE_MTLS_CERT"); v != "" {
		cfg.Auth.CertPath = v
	}
	if v := os.Getenv("ODINFORGE_MTLS_KEY"); v != "" {
		cfg.Auth.KeyPath = v
	}
	if v := os.Getenv("ODINFORGE_CA_CERT"); v != "" {
		cfg.Auth.CAPath = v
	}

	// Intervals
	if v := os.Getenv("ODINFORGE_TELEMETRY_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Collection.TelemetryInterval = d
		}
	}
	if v := os.Getenv("ODINFORGE_HEARTBEAT_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Collection.HeartbeatInterval = d
		}
	}

	// Buffer/Transport
	if v := os.Getenv("ODINFORGE_QUEUE_PATH"); v != "" {
		cfg.Buffer.Path = v
	}
	if v := os.Getenv("ODINFORGE_BATCH_SIZE"); v != "" {
		// quick parse
		if n, err := atoi(v); err == nil && n > 0 {
			cfg.Transport.BatchSize = n
		}
	}
	if v := os.Getenv("ODINFORGE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Transport.Timeout = d
		}
	}
	if v := os.Getenv("ODINFORGE_COMPRESS"); v != "" {
		cfg.Transport.Compress = (v == "1" || strings.EqualFold(v, "true"))
	}
	if v := os.Getenv("ODINFORGE_REQUIRE_HTTPS"); v != "" {
		cfg.Safety.RequireHTTPS = (v == "1" || strings.EqualFold(v, "true"))
	}
}

func IsHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.EqualFold(u.Scheme, "https")
}

func IsLocalhost(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1"
}

// tiny atoi to avoid importing strconv everywhere
func atoi(s string) (int, error) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("not int")
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}
