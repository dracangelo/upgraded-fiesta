package plugin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOSProcessSandboxExecution(t *testing.T) {
	cfg := DefaultSandboxConfig()
	sandbox := NewOSProcessSandbox(cfg)

	output, err := sandbox.ExecuteProcess(context.Background(), "echo", []string{"hello sandboxed world"}, nil)
	if err != nil {
		t.Fatalf("ExecuteProcess failed: %v", err)
	}
	if !strings.Contains(string(output), "hello sandboxed world") {
		t.Fatalf("expected output to contain 'hello sandboxed world', got %q", string(output))
	}
}

func TestOSProcessSandboxTimeout(t *testing.T) {
	cfg := DefaultSandboxConfig()
	cfg.MaxExecTime = 100 * time.Millisecond
	sandbox := NewOSProcessSandbox(cfg)

	start := time.Now()
	_, err := sandbox.ExecuteProcess(context.Background(), "sleep", []string{"1"}, nil)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrSandboxTimeout) {
		t.Fatalf("expected ErrSandboxTimeout, got %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("sandbox took too long to terminate process: %v", elapsed)
	}
}

func TestOSProcessSandboxEnvironmentSanitization(t *testing.T) {
	cfg := DefaultSandboxConfig()
	cfg.AllowedEnv = []string{
		"PATH=/usr/bin:/bin",
		"SAFE_VAR=allowed",
		"API_KEY=secret_key_12345",
		"DB_PASSWORD=supersecret",
		"AUTH_TOKEN=bearer_98765",
		"POSTGRES_DSN=postgres://user:pass@host/db",
	}
	sandbox := NewOSProcessSandbox(cfg)

	sanitized := sandbox.sanitizeEnvironment(t.TempDir())
	joined := strings.Join(sanitized, "\n")

	if strings.Contains(joined, "secret_key_12345") ||
		strings.Contains(joined, "supersecret") ||
		strings.Contains(joined, "bearer_98765") ||
		strings.Contains(joined, "postgres://") {
		t.Fatalf("sandbox environment leaked sensitive credentials: %s", joined)
	}
	if !strings.Contains(joined, "SAFE_VAR=allowed") {
		t.Fatalf("sandbox dropped safe environment variable: %s", joined)
	}
}

func TestOSProcessSandboxOutputLimit(t *testing.T) {
	cfg := DefaultSandboxConfig()
	cfg.MaxOutputBytes = 32
	sandbox := NewOSProcessSandbox(cfg)

	// Produce 100 bytes
	_, err := sandbox.ExecuteProcess(context.Background(), "echo", []string{strings.Repeat("A", 100)}, nil)
	if !errors.Is(err, ErrSandboxOutputLimit) {
		t.Fatalf("expected ErrSandboxOutputLimit, got %v", err)
	}
}

func TestOSProcessSandboxWorkingDirIsolation(t *testing.T) {
	tempDir := t.TempDir()
	cfg := DefaultSandboxConfig()
	cfg.IsolatedWorkingDir = tempDir
	sandbox := NewOSProcessSandbox(cfg)

	testFile := filepath.Join(tempDir, "isolated.txt")
	_, err := sandbox.ExecuteProcess(context.Background(), "sh", []string{"-c", "echo 'isolated content' > isolated.txt"}, nil)
	if err != nil {
		t.Fatalf("ExecuteProcess failed: %v", err)
	}

	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("failed to read written file in isolated dir: %v", err)
	}
	if !strings.Contains(string(content), "isolated content") {
		t.Fatalf("unexpected content: %q", string(content))
	}
}
