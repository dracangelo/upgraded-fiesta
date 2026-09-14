//go:build darwin

package plugin

import (
	"os/exec"
	"syscall"
)

func configurePlatformSandbox(cmd *exec.Cmd, _ SandboxConfig) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
}

func terminateProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	pgid := cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
}
