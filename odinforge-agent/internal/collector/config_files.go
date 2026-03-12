package collector

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// ConfigFileSignal represents a detected config/credential file.
// Only KEY names are reported — values are always redacted.
type ConfigFileSignal struct {
	Path string   `json:"path"`
	Type string   `json:"type"` // "env_file" | "cloud_credential" | "db_config" | "k8s_config"
	Keys []string `json:"keys"` // matched credential-like key names (values redacted)
}

// highValuePaths are config files commonly containing secrets.
var highValuePaths = []struct {
	relPath string
	sigType string
}{
	{".env", "env_file"},
	{".env.local", "env_file"},
	{".env.production", "env_file"},
	{".env.development", "env_file"},
	{".aws/credentials", "cloud_credential"},
	{".aws/config", "cloud_credential"},
	{".azure/accessTokens.json", "cloud_credential"},
	{".config/gcloud/application_default_credentials.json", "cloud_credential"},
	{".kube/config", "k8s_config"},
	{"config/database.yml", "db_config"},
	{".docker/config.json", "cloud_credential"},
}

// credentialKeyPattern matches key names that commonly hold secrets.
var credentialKeyPattern = regexp.MustCompile(
	`(?i)^[A-Z_]*(PASSWORD|SECRET|API_KEY|ACCESS_KEY|PRIVATE_KEY|TOKEN|DATABASE_URL|DB_PASSWORD|AWS_SECRET|CREDENTIALS)[A-Z_]*$`,
)

// GetConfigFileSignals scans well-known paths for config/credential files.
// It reports ONLY key names — values are NEVER read or transmitted.
func GetConfigFileSignals() []ConfigFileSignal {
	var signals []ConfigFileSignal

	homeDir := userHomeDir()
	if homeDir == "" {
		return signals
	}

	for _, hvp := range highValuePaths {
		fullPath := filepath.Join(homeDir, hvp.relPath)
		info, err := os.Stat(fullPath)
		if err != nil || info.IsDir() {
			continue
		}

		keys := extractKeyNames(fullPath)
		signals = append(signals, ConfigFileSignal{
			Path: hvp.relPath, // relative path only — no full filesystem path leaked
			Type: hvp.sigType,
			Keys: keys,
		})
	}

	// Also check common app directories
	appPaths := []string{"/app", "/opt", "/srv", "/var/www"}
	if runtime.GOOS == "darwin" {
		appPaths = []string{} // skip on macOS agent dev
	}
	for _, base := range appPaths {
		envPath := filepath.Join(base, ".env")
		info, err := os.Stat(envPath)
		if err != nil || info.IsDir() {
			continue
		}
		keys := extractKeyNames(envPath)
		signals = append(signals, ConfigFileSignal{
			Path: envPath,
			Type: "env_file",
			Keys: keys,
		})
	}

	return signals
}

// extractKeyNames reads a file and returns credential-like key names.
// For .env-style files (KEY=VALUE), only the KEY part is extracted.
// For JSON/YAML files, only top-level key-like patterns are matched.
// Values are NEVER captured.
func extractKeyNames(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var keys []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// .env style: KEY=VALUE or export KEY=VALUE
		if idx := strings.Index(line, "="); idx > 0 {
			key := strings.TrimPrefix(line[:idx], "export ")
			key = strings.TrimSpace(key)
			if credentialKeyPattern.MatchString(key) && !seen[key] {
				keys = append(keys, key)
				seen[key] = true
			}
		}

		// YAML style: key: value
		if idx := strings.Index(line, ":"); idx > 0 && !strings.Contains(line, "=") {
			key := strings.TrimSpace(line[:idx])
			key = strings.Trim(key, `"'`)
			upperKey := strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
			if credentialKeyPattern.MatchString(upperKey) && !seen[upperKey] {
				keys = append(keys, key)
				seen[upperKey] = true
			}
		}
	}

	return keys
}

func userHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}
