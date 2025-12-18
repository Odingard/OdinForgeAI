//go:build !windows

package installer

import "os"

func isRoot() bool {
	return os.Geteuid() == 0
}
