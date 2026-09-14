//go:build windows

package plugin

import (
	"os/exec"
	"syscall"
)

func configurePlatformSandbox(cmd *exec.Cmd, _ SandboxConfig) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}

func terminateProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
