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

        // Auto-registration: if APIKey is empty, use this token to auto-register
        RegistrationToken string `yaml:"registration_token"`
        APIKeyStorePath   string `yaml:"api_key_store_path"` // where to persist auto-registered key
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
                        Mode:            "api_key",
                        APIKeyStorePath: "/var/lib/odinforge-agent/api_key",
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
        // Server - check both namespaced and simple env vars
        if v := getEnvAny("ODINFORGE_SERVER_URL", "SERVER_URL", "ODINFORGE_SERVER"); v != "" {
                cfg.Server.URL = v
        }
        if v := getEnvAny("ODINFORGE_VERIFY_TLS", "VERIFY_TLS"); v != "" {
                cfg.Server.VerifyTLS = (v == "1" || strings.EqualFold(v, "true"))
        }
        if v := getEnvAny("ODINFORGE_PINNED_SPKI", "PINNED_SPKI"); v != "" {
                cfg.Server.PinnedSPKI = v
        }

        // Auth - check both namespaced and simple env vars
        if v := getEnvAny("ODINFORGE_TENANT_ID", "TENANT_ID"); v != "" {
                cfg.Auth.TenantID = v
        }
        if v := getEnvAny("ODINFORGE_AUTH_MODE", "AUTH_MODE"); v != "" {
                cfg.Auth.Mode = v
        }
        if v := getEnvAny("ODINFORGE_API_KEY", "API_KEY"); v != "" {
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
        if v := getEnvAny("ODINFORGE_REGISTRATION_TOKEN", "REGISTRATION_TOKEN", "TOKEN"); v != "" {
                cfg.Auth.RegistrationToken = v
        }
        if v := getEnvAny("ODINFORGE_API_KEY_STORE_PATH", "API_KEY_STORE_PATH"); v != "" {
                cfg.Auth.APIKeyStorePath = v
        }

        // Intervals - support both duration strings and simple seconds
        if v := getEnvAny("ODINFORGE_TELEMETRY_INTERVAL", "TELEMETRY_INTERVAL", "INTERVAL"); v != "" {
                cfg.Collection.TelemetryInterval = parseDurationOrSeconds(v, cfg.Collection.TelemetryInterval)
        }
        if v := getEnvAny("ODINFORGE_HEARTBEAT_INTERVAL", "HEARTBEAT_INTERVAL"); v != "" {
                cfg.Collection.HeartbeatInterval = parseDurationOrSeconds(v, cfg.Collection.HeartbeatInterval)
        }

        // Buffer/Transport
        if v := getEnvAny("ODINFORGE_QUEUE_PATH", "QUEUE_PATH"); v != "" {
                cfg.Buffer.Path = v
        }
        if v := getEnvAny("ODINFORGE_BATCH_SIZE", "BATCH_SIZE"); v != "" {
                if n, err := atoi(v); err == nil && n > 0 {
                        cfg.Transport.BatchSize = n
                }
        }
        if v := getEnvAny("ODINFORGE_TIMEOUT", "TIMEOUT"); v != "" {
                cfg.Transport.Timeout = parseDurationOrSeconds(v, cfg.Transport.Timeout)
        }
        if v := getEnvAny("ODINFORGE_COMPRESS", "COMPRESS"); v != "" {
                cfg.Transport.Compress = (v == "1" || strings.EqualFold(v, "true"))
        }
        if v := getEnvAny("ODINFORGE_REQUIRE_HTTPS", "REQUIRE_HTTPS"); v != "" {
                cfg.Safety.RequireHTTPS = (v == "1" || strings.EqualFold(v, "true"))
        }

        // Container-friendly: disable persistent queue if running stateless
        if v := getEnvAny("ODINFORGE_STATELESS", "STATELESS"); v != "" {
                if v == "1" || strings.EqualFold(v, "true") {
                        cfg.Buffer.Path = "/tmp/odinforge-agent.queue.db"
                        cfg.Auth.APIKeyStorePath = "/tmp/odinforge-api-key"
                }
        }
}

// getEnvAny returns the first non-empty environment variable from the list
func getEnvAny(keys ...string) string {
        for _, key := range keys {
                if v := os.Getenv(key); v != "" {
                        return v
                }
        }
        return ""
}

// parseDurationOrSeconds parses a duration string or plain number as seconds
func parseDurationOrSeconds(v string, fallback time.Duration) time.Duration {
        // Try parsing as duration first (e.g., "5m", "300s", "1h")
        if d, err := time.ParseDuration(v); err == nil {
                return d
        }
        // Try parsing as plain number (seconds)
        if n, err := atoi(v); err == nil && n > 0 {
                return time.Duration(n) * time.Second
        }
        return fallback
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
