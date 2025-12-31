//go:build !windows

package service

import (
	"context"
)

func IsWindowsService() bool {
	return false
}

func RunAsService(name string, runFunc func(ctx context.Context)) error {
	runFunc(context.Background())
	return nil
}
