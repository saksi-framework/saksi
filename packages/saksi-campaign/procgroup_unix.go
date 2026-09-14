//go:build !windows

package campaign

import (
	"os/exec"
	"syscall"
)

// killProcessGroup starts cmd in its own process group and makes cancelling it
// kill the whole group, so a timed-out script takes its children with it.
func killProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
