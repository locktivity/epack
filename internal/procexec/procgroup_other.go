//go:build !unix

package procexec

import "os/exec"

func isolateProcessGroup(*exec.Cmd, bool) {}
