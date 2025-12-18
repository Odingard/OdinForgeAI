//go:build windows

package installer

import (
        "os/exec"
        "strings"
)

func isRoot() bool {
        return isWindowsAdminCheck()
}

func isWindowsAdminCheck() bool {
        // Try to run a command that requires admin privileges
        // net session is a reliable way to check for admin on Windows
        cmd := exec.Command("net", "session")
        cmd.Stdout = nil
        cmd.Stderr = nil
        err := cmd.Run()
        return err == nil
}

// Alternative check using whoami
func isWindowsAdminWhoami() bool {
        out, err := exec.Command("whoami", "/groups").Output()
        if err != nil {
                return false
        }
        // Check for Administrators group SID
        return strings.Contains(string(out), "S-1-5-32-544")
}
