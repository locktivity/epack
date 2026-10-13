//go:build unix

package procexec

import (
	"errors"
	"os/exec"
	"syscall"
)

// isolateProcessGroup gives the child its own process group and, when the
// command has a context, has cancellation signal the whole group. A group
// that has already exited is not an error.
func isolateProcessGroup(cmd *exec.Cmd, withContext bool) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if !withContext {
		return
	}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
}
