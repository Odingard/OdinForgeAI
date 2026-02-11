package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"odinforge-agent/internal/config"
	"odinforge-agent/internal/logger"
)

var log = logger.WithComponent("updater")

// VersionInfo from the server
type VersionInfo struct {
	Version     string `json:"version"`
	DownloadURL string `json:"downloadUrl"`
	Checksum    string `json:"checksum"` // SHA256
	ReleaseDate string `json:"releaseDate"`
	Mandatory   bool   `json:"mandatory"`
}

// Updater handles agent self-update
type Updater struct {
	cfg            config.Config
	currentVersion string
	client         *http.Client
	checkInterval  time.Duration
}

// New creates an updater
func New(cfg config.Config, currentVersion string) *Updater {
	return &Updater{
		cfg:            cfg,
		currentVersion: currentVersion,
		client:         &http.Client{Timeout: 60 * time.Second},
		checkInterval:  1 * time.Hour,
	}
}

// Run starts the periodic update check loop
func (u *Updater) Run(ctx context.Context) {
	// Initial delay to let agent stabilize
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Minute):
	}

	ticker := time.NewTicker(u.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := u.checkAndUpdate(ctx); err != nil {
				log.Warn("update check failed", "error", err.Error())
			}
		}
	}
}

func (u *Updater) checkAndUpdate(ctx context.Context) error {
	info, err := u.checkVersion(ctx)
	if err != nil {
		return fmt.Errorf("version check: %w", err)
	}

	if info == nil || info.Version == u.currentVersion {
		log.Debug("agent is up to date", "version", u.currentVersion)
		return nil
	}

	log.Info("new version available",
		"current", u.currentVersion,
		"available", info.Version,
		"mandatory", info.Mandatory,
	)

	if err := u.downloadAndReplace(ctx, info); err != nil {
		return fmt.Errorf("update failed: %w", err)
	}

	log.Info("update downloaded, restart required", "new_version", info.Version)
	// The service manager (systemd/launchd) will restart us
	os.Exit(0)
	return nil
}

func (u *Updater) checkVersion(ctx context.Context) (*VersionInfo, error) {
	url := strings.TrimRight(u.cfg.Server.URL, "/") + "/api/agents/version"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-Key", u.cfg.Auth.APIKey)
	req.Header.Set("X-Agent-Version", u.currentVersion)
	req.Header.Set("X-Agent-Platform", runtime.GOOS+"/"+runtime.GOARCH)

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// 204 = no update available
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var info VersionInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}

	return &info, nil
}

func (u *Updater) downloadAndReplace(ctx context.Context, info *VersionInfo) error {
	// Determine download URL
	downloadURL := info.DownloadURL
	if downloadURL == "" {
		platform := runtime.GOOS + "-" + runtime.GOARCH
		suffix := ""
		if runtime.GOOS == "windows" {
			suffix = ".exe"
		}
		downloadURL = strings.TrimRight(u.cfg.Server.URL, "/") +
			"/api/agents/download/" + platform + suffix
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %d", resp.StatusCode)
	}

	// Get current binary path
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("cannot resolve symlinks: %w", err)
	}

	// Download to temp file next to current binary
	tmpPath := execPath + ".update"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("download write failed: %w", err)
	}
	tmpFile.Close()

	// Make executable
	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("chmod failed: %w", err)
	}

	// Atomic replace: rename old, rename new, remove old
	backupPath := execPath + ".backup"
	os.Remove(backupPath) // clean up any previous backup

	if err := os.Rename(execPath, backupPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("backup rename failed: %w", err)
	}

	if err := os.Rename(tmpPath, execPath); err != nil {
		// Rollback
		os.Rename(backupPath, execPath)
		return fmt.Errorf("update rename failed: %w", err)
	}

	// Leave backup for one cycle in case of issues
	log.Info("binary replaced successfully",
		"path", execPath,
		"backup", backupPath,
	)

	return nil
}
