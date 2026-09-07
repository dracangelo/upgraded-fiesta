package modules

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	defaultGitHistoryCommits = 250
	maxGitHistoryCommits     = 2000
	maxGitHistoryBytes       = 1 << 20
)

// GitSecretFinding contains no recovered credential material. The commit ID
// and redacted fingerprint let an authorized repository owner remediate the
// source without this tool retaining a usable secret.
type GitSecretFinding struct {
	Commit string
	Match  SecretMatch
}

// ScanGitHistory examines an explicitly named local Git worktree. It neither
// contacts a remote nor modifies the repository. The bounded commit and byte
// limits keep it suitable for operator workstations and CI remediation jobs.
func ScanGitHistory(ctx context.Context, repository string, maxCommits int) ([]GitSecretFinding, error) {
	repository, err := explicitGitWorktree(ctx, repository)
	if err != nil {
		return nil, err
	}
	if maxCommits <= 0 {
		maxCommits = defaultGitHistoryCommits
	}
	if maxCommits > maxGitHistoryCommits {
		return nil, fmt.Errorf("max commits must not exceed %d", maxGitHistoryCommits)
	}
	commits, err := gitOutput(ctx, repository, "rev-list", "--all", fmt.Sprintf("--max-count=%d", maxCommits))
	if err != nil {
		return nil, fmt.Errorf("list repository history: %w", err)
	}
	seen := make(map[string]bool)
	findings := make([]GitSecretFinding, 0)
	for _, commit := range strings.Fields(string(commits)) {
		content, err := gitOutputLimited(ctx, repository, maxGitHistoryBytes, "show", "--format=", "--no-ext-diff", "--no-textconv", commit)
		if err != nil {
			return nil, fmt.Errorf("read commit %s: %w", commit, err)
		}
		for _, match := range detectSecrets(string(content)) {
			key := match.Kind + ":" + match.Redacted
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, GitSecretFinding{Commit: commit, Match: match})
		}
	}
	return findings, nil
}

func explicitGitWorktree(ctx context.Context, repository string) (string, error) {
	if strings.TrimSpace(repository) == "" {
		return "", fmt.Errorf("repository path is required")
	}
	abs, err := filepath.Abs(repository)
	if err != nil {
		return "", fmt.Errorf("resolve repository path: %w", err)
	}
	abs, err = filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("resolve repository path: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("repository path %q is not a directory", repository)
	}
	inside, err := gitOutput(ctx, abs, "rev-parse", "--is-inside-work-tree")
	if err != nil || strings.TrimSpace(string(inside)) != "true" {
		return "", fmt.Errorf("repository path %q is not a Git worktree", repository)
	}
	return abs, nil
}

func gitOutput(ctx context.Context, repository string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repository}, args...)...)
	return cmd.Output()
}

func gitOutputLimited(ctx context.Context, repository string, limit int64, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repository}, args...)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	content, readErr := io.ReadAll(io.LimitReader(stdout, limit+1))
	waitErr := cmd.Wait()
	if readErr != nil {
		return nil, readErr
	}
	if len(content) > int(limit) {
		return nil, fmt.Errorf("commit output exceeds %d bytes", limit)
	}
	if waitErr != nil {
		return nil, waitErr
	}
	return content, nil
}
