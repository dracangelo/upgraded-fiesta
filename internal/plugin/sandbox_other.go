//go:build !linux && !darwin && !windows

package plugin

import (
	"os/exec"
)

func configurePlatformSandbox(cmd *exec.Cmd, _ SandboxConfig) {}

func terminateProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
