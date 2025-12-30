//go:build windows

package collector

func getCPUPercent() float64 {
	return 0.0
}

func getMemoryPercent() float64 {
	return 0.0
}

func getDiskPercent() float64 {
	return 0.0
}
