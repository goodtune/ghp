//go:build windows

package server

import (
	"log/slog"
	"os"
	"syscall"
)

func shutdownSignals() []os.Signal {
	return []os.Signal{syscall.SIGTERM, syscall.SIGINT}
}

func setupPlatformSignals(_ *slog.Logger, _ func()) {
	// No SIGUSR1 equivalent on Windows.
}
