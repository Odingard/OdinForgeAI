package collector

import (
	"time"
)

type Metrics struct {
	CPUPercent   float64 `json:"cpu_percent"`
	MemUsedPct   float64 `json:"mem_used_pct"`
	DiskUsedPct  float64 `json:"disk_used_pct"`
	CollectedUTC string  `json:"collected_utc"`
}

func GetMetrics() Metrics {
	return Metrics{
		CPUPercent:   getCPUPercent(),
		MemUsedPct:   getMemoryPercent(),
		DiskUsedPct:  getDiskPercent(),
		CollectedUTC: time.Now().UTC().Format(time.RFC3339),
	}
}

func parseUint64(s string) uint64 {
	var result uint64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			result = result*10 + uint64(c-'0')
		} else {
			break
		}
	}
	return result
}
