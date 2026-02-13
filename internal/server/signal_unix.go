//go:build !windows

package server

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func shutdownSignals() []os.Signal {
	return []os.Signal{syscall.SIGTERM, syscall.SIGINT}
}

func setupPlatformSignals(logger *slog.Logger) {
	sigUSR1 := make(chan os.Signal, 1)
	signal.Notify(sigUSR1, syscall.SIGUSR1)
	go func() {
		for range sigUSR1 {
			logger.Info("received SIGUSR1, reopening log files")
		}
	}()
}
