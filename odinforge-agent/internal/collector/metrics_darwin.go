//go:build darwin

package collector

import (
        "os/exec"
        "runtime"
        "strconv"
        "strings"
        "syscall"
)

func getCPUPercent() float64 {
        out, err := exec.Command("ps", "-A", "-o", "%cpu").Output()
        if err != nil {
                return 0.0
        }

        lines := strings.Split(string(out), "\n")
        var total float64
        for i, line := range lines {
                if i == 0 {
                        continue
                }
                line = strings.TrimSpace(line)
                if line == "" {
                        continue
                }
                if val, err := strconv.ParseFloat(line, 64); err == nil {
                        total += val
                }
        }
        numCPU := float64(runtime.NumCPU())
        if numCPU > 1 {
                total = total / numCPU
        }
        if total > 100.0 {
                total = 100.0
        }
        return total
}

func getMemoryPercent() float64 {
        out, err := exec.Command("vm_stat").Output()
        if err != nil {
                return 0.0
        }

        lines := strings.Split(string(out), "\n")
        var pagesFree, pagesActive, pagesInactive, pagesWired uint64

        for _, line := range lines {
                if strings.HasPrefix(line, "Pages free:") {
                        pagesFree = extractNumber(line)
                } else if strings.HasPrefix(line, "Pages active:") {
                        pagesActive = extractNumber(line)
                } else if strings.HasPrefix(line, "Pages inactive:") {
                        pagesInactive = extractNumber(line)
                } else if strings.HasPrefix(line, "Pages wired down:") {
                        pagesWired = extractNumber(line)
                }
        }

        total := pagesFree + pagesActive + pagesInactive + pagesWired
        if total == 0 {
                return 0.0
        }

        used := pagesActive + pagesWired
        return 100.0 * float64(used) / float64(total)
}

func extractNumber(line string) uint64 {
        var result uint64
        inNumber := false
        for _, c := range line {
                if c >= '0' && c <= '9' {
                        inNumber = true
                        result = result*10 + uint64(c-'0')
                } else if inNumber {
                        break
                }
        }
        return result
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
