//go:build windows

package collector

import (
	"bytes"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetDiskFreeSpaceExW  = kernel32.NewProc("GetDiskFreeSpaceExW")
)

type memoryStatusEx struct {
	dwLength                uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

func getCPUPercent() float64 {
	idle1, kernel1, user1 := getSystemTimes()
	time.Sleep(100 * time.Millisecond)
	idle2, kernel2, user2 := getSystemTimes()

	idleDelta := idle2 - idle1
	kernelDelta := kernel2 - kernel1
	userDelta := user2 - user1

	totalDelta := kernelDelta + userDelta
	if totalDelta == 0 {
		return getCPUPercentFromWMIC()
	}

	return 100.0 * (1.0 - float64(idleDelta)/float64(totalDelta))
}

func getSystemTimes() (idle, kernel, user uint64) {
	var idleTime, kernelTime, userTime syscall.Filetime
	
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getSystemTimes := kernel32.NewProc("GetSystemTimes")
	
	ret, _, _ := getSystemTimes.Call(
		uintptr(unsafe.Pointer(&idleTime)),
		uintptr(unsafe.Pointer(&kernelTime)),
		uintptr(unsafe.Pointer(&userTime)),
	)
	
	if ret == 0 {
		return 0, 0, 0
	}
	
	idle = uint64(idleTime.HighDateTime)<<32 | uint64(idleTime.LowDateTime)
	kernel = uint64(kernelTime.HighDateTime)<<32 | uint64(kernelTime.LowDateTime)
	user = uint64(userTime.HighDateTime)<<32 | uint64(userTime.LowDateTime)
	
	return idle, kernel, user
}

func getCPUPercentFromWMIC() float64 {
	cmd := exec.Command("wmic", "cpu", "get", "loadpercentage")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return 0.0
	}
	
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != "LoadPercentage" {
			val, err := strconv.ParseFloat(line, 64)
			if err == nil {
				return val
			}
		}
	}
	return 0.0
}

func getMemoryPercent() float64 {
	var memStatus memoryStatusEx
	memStatus.dwLength = uint32(unsafe.Sizeof(memStatus))
	
	ret, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStatus)))
	if ret == 0 {
		return getMemoryPercentFromWMIC()
	}
	
	return float64(memStatus.dwMemoryLoad)
}

func getMemoryPercentFromWMIC() float64 {
	cmd := exec.Command("wmic", "OS", "get", "FreePhysicalMemory,TotalVisibleMemorySize", "/format:list")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return 0.0
	}
	
	var freeKB, totalKB uint64
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "FreePhysicalMemory=") {
			val := strings.TrimPrefix(line, "FreePhysicalMemory=")
			freeKB, _ = strconv.ParseUint(strings.TrimSpace(val), 10, 64)
		} else if strings.HasPrefix(line, "TotalVisibleMemorySize=") {
			val := strings.TrimPrefix(line, "TotalVisibleMemorySize=")
			totalKB, _ = strconv.ParseUint(strings.TrimSpace(val), 10, 64)
		}
	}
	
	if totalKB == 0 {
		return 0.0
	}
	
	usedKB := totalKB - freeKB
	return 100.0 * float64(usedKB) / float64(totalKB)
}

func getDiskPercent() float64 {
	path, _ := syscall.UTF16PtrFromString("C:\\")
	
	var freeBytesAvailable, totalBytes, freeBytes uint64
	
	ret, _, _ := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalBytes)),
		uintptr(unsafe.Pointer(&freeBytes)),
	)
	
	if ret == 0 || totalBytes == 0 {
		return getDiskPercentFromWMIC()
	}
	
	usedBytes := totalBytes - freeBytes
	return 100.0 * float64(usedBytes) / float64(totalBytes)
}

func getDiskPercentFromWMIC() float64 {
	cmd := exec.Command("wmic", "logicaldisk", "where", "DeviceID='C:'", "get", "Size,FreeSpace", "/format:list")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return 0.0
	}
	
	var freeSpace, size uint64
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "FreeSpace=") {
			val := strings.TrimPrefix(line, "FreeSpace=")
			freeSpace, _ = strconv.ParseUint(strings.TrimSpace(val), 10, 64)
		} else if strings.HasPrefix(line, "Size=") {
			val := strings.TrimPrefix(line, "Size=")
			size, _ = strconv.ParseUint(strings.TrimSpace(val), 10, 64)
		}
	}
	
	if size == 0 {
		return 0.0
	}
	
	usedSpace := size - freeSpace
	return 100.0 * float64(usedSpace) / float64(size)
}
