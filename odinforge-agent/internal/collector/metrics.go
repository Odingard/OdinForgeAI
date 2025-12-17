package collector

import (
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/mem"
)

type Metrics struct {
	CPUPercent   float64 `json:"cpu_percent"`
	MemUsedPct   float64 `json:"mem_used_pct"`
	DiskUsedPct  float64 `json:"disk_used_pct"`
	CollectedUTC string  `json:"collected_utc"`
}

func GetMetrics() Metrics {
	cpuPct := 0.0
	if p, err := cpu.Percent(500*time.Millisecond, false); err == nil && len(p) > 0 {
		cpuPct = p[0]
	}

	memPct := 0.0
	if v, err := mem.VirtualMemory(); err == nil {
		memPct = v.UsedPercent
	}

	diskPct := 0.0
	if u, err := disk.Usage("/"); err == nil {
		diskPct = u.UsedPercent
	}

	return Metrics{
		CPUPercent:   cpuPct,
		MemUsedPct:   memPct,
		DiskUsedPct:  diskPct,
		CollectedUTC: time.Now().UTC().Format(time.RFC3339),
	}
}
