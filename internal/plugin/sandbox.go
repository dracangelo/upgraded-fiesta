package plugin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"enumscan/internal/models"
)

var (
	ErrSandboxTimeout     = errors.New("plugin execution sandboxed: execution timeout exceeded")
	ErrSandboxOutputLimit = errors.New("plugin execution sandboxed: output limit exceeded")
	ErrSandboxExecFailed  = errors.New("plugin execution sandboxed: process execution failed")
)

// SandboxConfig controls OS-level process isolation parameters.
type SandboxConfig struct {
	MaxExecTime        time.Duration
	MaxMemoryBytes     int64
	MaxOutputBytes     int64
	AllowNetwork       bool
	AllowedEnv         []string
	IsolatedWorkingDir string
}

// DefaultSandboxConfig returns conservative, safe sandbox boundaries.
func DefaultSandboxConfig() SandboxConfig {
	return SandboxConfig{
		MaxExecTime:    5 * time.Second,
		MaxMemoryBytes: 128 * 1024 * 1024, // 128 MB
		MaxOutputBytes: 1 * 1024 * 1024,   // 1 MB
		AllowNetwork:   false,
		AllowedEnv: []string{
			"PATH=/usr/local/bin:/usr/bin:/bin",
			"LC_ALL=C.UTF-8",
			"LANG=C.UTF-8",
		},
	}
}

// OSProcessSandbox provides cross-platform, OS-level process isolation for untrusted plugins.
type OSProcessSandbox struct {
	config SandboxConfig
}

// NewOSProcessSandbox creates a new sandbox supervisor with the provided configuration.
func NewOSProcessSandbox(config SandboxConfig) *OSProcessSandbox {
	if config.MaxExecTime <= 0 {
		config.MaxExecTime = 5 * time.Second
	}
	if config.MaxMemoryBytes <= 0 {
		config.MaxMemoryBytes = 128 * 1024 * 1024
	}
	if config.MaxOutputBytes <= 0 {
		config.MaxOutputBytes = 1 * 1024 * 1024
	}
	if len(config.AllowedEnv) == 0 {
		config.AllowedEnv = DefaultSandboxConfig().AllowedEnv
	}
	return &OSProcessSandbox{config: config}
}

// ExecuteProcess runs an executable in an isolated OS process with restricted environment,
// separate process group, bounded output, and strict execution timeout.
func (s *OSProcessSandbox) ExecuteProcess(ctx context.Context, executable string, args []string, stdin []byte) ([]byte, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, s.config.MaxExecTime)
	defer cancel()

	workDir := s.config.IsolatedWorkingDir
	var cleanupDir func()
	if workDir == "" {
		tempDir, err := os.MkdirTemp("", "enumscan-sandbox-*")
		if err != nil {
			return nil, fmt.Errorf("create sandbox working directory: %w", err)
		}
		workDir = tempDir
		cleanupDir = func() { _ = os.RemoveAll(tempDir) }
	}
	if cleanupDir != nil {
		defer cleanupDir()
	}

	cmd := exec.CommandContext(ctxTimeout, executable, args...)
	cmd.Dir = workDir
	cmd.Env = s.sanitizeEnvironment(workDir)

	// Platform-specific process isolation (process group, sys limits)
	configurePlatformSandbox(cmd, s.config)

	if len(stdin) > 0 {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	var stdoutBuf bytes.Buffer
	limitWriter := &boundedWriter{
		w:     &stdoutBuf,
		limit: s.config.MaxOutputBytes,
	}
	cmd.Stdout = limitWriter

	err := cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSandboxExecFailed, err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-ctxTimeout.Done():
		terminateProcessGroup(cmd)
		<-done
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, ctx.Err()
		}
		return nil, ErrSandboxTimeout

	case waitErr := <-done:
		if limitWriter.exceeded {
			return stdoutBuf.Bytes(), ErrSandboxOutputLimit
		}
		if waitErr != nil {
			return stdoutBuf.Bytes(), fmt.Errorf("%w: %v", ErrSandboxExecFailed, waitErr)
		}
		return stdoutBuf.Bytes(), nil
	}
}

// sanitizeEnvironment ensures no sensitive environment variables (API keys, credentials,
// database URLs) are leaked into the sandboxed process.
func (s *OSProcessSandbox) sanitizeEnvironment(tempDir string) []string {
	env := make([]string, 0, len(s.config.AllowedEnv)+3)
	for _, e := range s.config.AllowedEnv {
		key := strings.SplitN(e, "=", 2)[0]
		upper := strings.ToUpper(key)
		if strings.Contains(upper, "KEY") || strings.Contains(upper, "SECRET") ||
			strings.Contains(upper, "TOKEN") || strings.Contains(upper, "PASS") ||
			strings.Contains(upper, "DSN") || strings.Contains(upper, "AUTH") {
			continue
		}
		env = append(env, e)
	}
	env = append(env, "TMPDIR="+tempDir, "TEMP="+tempDir, "TMP="+tempDir)
	return env
}

// boundedWriter wraps an io.Writer and aborts if limit is exceeded.
type boundedWriter struct {
	w        io.Writer
	limit    int64
	written  int64
	exceeded bool
}

func (bw *boundedWriter) Write(p []byte) (n int, err error) {
	if bw.written+int64(len(p)) > bw.limit {
		bw.exceeded = true
		allowed := bw.limit - bw.written
		if allowed > 0 {
			n, _ = bw.w.Write(p[:allowed])
			bw.written += int64(n)
		}
		return len(p), nil
	}
	n, err = bw.w.Write(p)
	bw.written += int64(n)
	return n, err
}

// PluginSandbox provides both in-process safe dispatch and OS-level process isolation.
type PluginSandbox struct {
	maxExecTime time.Duration
	osSandbox   *OSProcessSandbox
}

// NewPluginSandbox creates a sandbox with the specified timeout.
func NewPluginSandbox(timeout time.Duration) *PluginSandbox {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	cfg := DefaultSandboxConfig()
	cfg.MaxExecTime = timeout
	return &PluginSandbox{
		maxExecTime: timeout,
		osSandbox:   NewOSProcessSandbox(cfg),
	}
}

// OSProcessSandbox returns the underlying OS process supervisor.
func (s *PluginSandbox) OSProcessSandbox() *OSProcessSandbox {
	return s.osSandbox
}

// ExecuteSandboxed executes an in-memory plugin function with recover and timeout protection.
func (s *PluginSandbox) ExecuteSandboxed(ctx context.Context, fn func(ctx context.Context) ([]models.Event, error)) ([]models.Event, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, s.maxExecTime)
	defer cancel()

	type result struct {
		events []models.Event
		err    error
	}

	resChan := make(chan result, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				resChan <- result{nil, fmt.Errorf("plugin panic recovered: %v", r)}
			}
		}()
		events, err := fn(ctxTimeout)
		resChan <- result{events, err}
	}()

	select {
	case res := <-resChan:
		return res.events, res.err
	case <-ctxTimeout.Done():
		return nil, ErrSandboxTimeout
	}
}
