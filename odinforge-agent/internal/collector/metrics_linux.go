//go:build linux

package collector

import (
	"bufio"
	"os"
	"strings"
	"syscall"
	"time"
)

func getCPUPercent() float64 {
	idle1, total1 := readCPUStat()
	time.Sleep(100 * time.Millisecond)
	idle2, total2 := readCPUStat()

	idleDelta := idle2 - idle1
	totalDelta := total2 - total1

	if totalDelta == 0 {
		return 0.0
	}

	return 100.0 * (1.0 - float64(idleDelta)/float64(totalDelta))
}

func readCPUStat() (idle, total uint64) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				for i := 1; i < len(fields) && i <= 10; i++ {
					val := parseUint64(fields[i])
					total += val
					if i == 4 {
						idle = val
					}
				}
			}
			break
		}
	}
	return idle, total
}

func getMemoryPercent() float64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0.0
	}
	defer f.Close()

	var memTotal, memAvailable uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memTotal = parseUint64(fields[1])
			}
		} else if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				memAvailable = parseUint64(fields[1])
			}
		}
	}

	if memTotal == 0 {
		return 0.0
	}

	used := memTotal - memAvailable
	return 100.0 * float64(used) / float64(memTotal)
}

func getDiskPercent() float64 {
	var stat syscall.Statfs_t
	path := "/"

	if err := syscall.Statfs(path, &stat); err != nil {
		return 0.0
	}

	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)

	if total == 0 {
		return 0.0
	}

	used := total - free
	return 100.0 * float64(used) / float64(total)
}
