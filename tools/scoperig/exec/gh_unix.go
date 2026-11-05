//go:build unix

package exec

import (
	osexec "os/exec"
	"syscall"
)

// SetProcessGroup runs a gh command in its own process group and makes cancellation
// SIGKILL the whole group, so pagers, credential helpers or other children
// gh starts cannot outlive the timeout.
func SetProcessGroup(cmd *osexec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
