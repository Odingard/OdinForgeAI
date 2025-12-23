package registrar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"odinforge-agent/internal/collector"
	"odinforge-agent/internal/config"
)

type AutoRegisterRequest struct {
	Token           string   `json:"token"`
	AgentName       string   `json:"agentName,omitempty"`
	Hostname        string   `json:"hostname,omitempty"`
	Platform        string   `json:"platform,omitempty"`
	PlatformVersion string   `json:"platformVersion,omitempty"`
	Architecture    string   `json:"architecture,omitempty"`
	Capabilities    []string `json:"capabilities,omitempty"`
	Environment     string   `json:"environment,omitempty"`
	Tags            []string `json:"tags,omitempty"`
}

type AutoRegisterResponse struct {
	ID            string `json:"id"`
	APIKey        string `json:"apiKey"`
	AgentName     string `json:"agentName"`
	Message       string `json:"message"`
	ExistingAgent bool   `json:"existingAgent"`
}

func EnsureAPIKey(cfg *config.Config) error {
	if cfg.Auth.APIKey != "" {
		return nil
	}

	if cfg.Auth.RegistrationToken == "" {
		return fmt.Errorf("no API key configured and no registration token available for auto-registration")
	}

	storedKey, err := loadStoredAPIKey(cfg.Auth.APIKeyStorePath)
	if err == nil && storedKey != "" {
		cfg.Auth.APIKey = storedKey
		return nil
	}

	key, err := autoRegister(cfg)
	if err != nil {
		return fmt.Errorf("auto-registration failed: %w", err)
	}

	if err := saveAPIKey(cfg.Auth.APIKeyStorePath, key); err != nil {
		return fmt.Errorf("failed to persist API key: %w", err)
	}

	cfg.Auth.APIKey = key
	return nil
}

func loadStoredAPIKey(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("no API key store path configured")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", fmt.Errorf("stored API key is empty")
	}

	return key, nil
}

func saveAPIKey(path, key string) error {
	if path == "" {
		return fmt.Errorf("no API key store path configured")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	if err := os.WriteFile(path, []byte(key), 0600); err != nil {
		return fmt.Errorf("failed to write API key: %w", err)
	}

	return nil
}

func autoRegister(cfg *config.Config) (string, error) {
	hostname, _ := os.Hostname()
	agentID := collector.StableAgentID()

	req := AutoRegisterRequest{
		Token:        cfg.Auth.RegistrationToken,
		AgentName:    hostname,
		Hostname:     hostname,
		Platform:     runtime.GOOS,
		Architecture: runtime.GOARCH,
		Environment:  "production",
		Tags:         []string{"auto-registered", "agent-id:" + agentID},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request: %w", err)
	}

	url := strings.TrimRight(cfg.Server.URL, "/") + "/api/agents/auto-register"

	client := &http.Client{Timeout: 30 * time.Second}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auto-registration failed (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result AutoRegisterResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if result.APIKey == "" {
		return "", fmt.Errorf("server returned empty API key")
	}

	return result.APIKey, nil
}
