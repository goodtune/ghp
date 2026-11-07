//go:build unix

package exec

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestGH_TimeoutKillsProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := runFakeGH(t, ctx, ghScenario("spawn", pidFile)); err == nil {
		t.Fatal("want rig error on timeout")
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("child pid: %v", err)
	}
	pid, err := strconv.Atoi(string(b))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("child %d still alive after timeout", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
