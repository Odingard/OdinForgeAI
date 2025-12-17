package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime"

	"github.com/shirou/gopsutil/v4/host"
)

type SystemInfo struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Platform     string `json:"platform"`
	PlatformVer  string `json:"platform_version"`
	KernelVer    string `json:"kernel_version"`
	Arch         string `json:"arch"`
	BootTimeUnix uint64 `json:"boot_time_unix"`
}

func GetSystemInfo() (SystemInfo, error) {
	h, _ := os.Hostname()
	hi, err := host.Info()
	if err != nil {
		return SystemInfo{}, err
	}
	return SystemInfo{
		Hostname:     h,
		OS:           runtime.GOOS,
		Platform:     hi.Platform,
		PlatformVer:  hi.PlatformVersion,
		KernelVer:    hi.KernelVersion,
		Arch:         runtime.GOARCH,
		BootTimeUnix: hi.BootTime,
	}, nil
}

// StableAgentID: best-effort stable ID.
// In containers, HOSTNAME changes; this still gives consistency per host/container runtime.
func StableAgentID() string {
	h, _ := os.Hostname()
	sum := sha256.Sum256([]byte(h + "|" + runtime.GOOS + "|" + runtime.GOARCH))
	return "agent_" + hex.EncodeToString(sum[:8]) // short but stable enough for v1
}
