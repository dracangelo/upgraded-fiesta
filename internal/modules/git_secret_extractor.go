package modules

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

// GitSecretExtractor analyzes Git repository commit histories for leaked credentials
// with bounded commit depth and strict cryptographic fingerprint redaction.
type GitSecretExtractor struct {
	db       store.RuntimeStore
	guard    scope.Guard
	maxDepth int
}

// NewGitSecretExtractor constructs a new git secret extractor.
func NewGitSecretExtractor(db store.RuntimeStore, guard scope.Guard, maxDepth int) *GitSecretExtractor {
	if maxDepth <= 0 {
		maxDepth = 50
	}
	if maxDepth > 200 {
		maxDepth = 200
	}
	return &GitSecretExtractor{
		db:       db,
		guard:    guard,
		maxDepth: maxDepth,
	}
}

// ScanRepositoryHistory scans git commits and diffs up to maxDepth.
func (e *GitSecretExtractor) ScanRepositoryHistory(
	ctx context.Context,
	scanID, repoPath string,
	maxDepth int,
) ([]models.Finding, error) {
	if maxDepth <= 0 {
		maxDepth = e.maxDepth
	}
	if maxDepth > 200 {
		maxDepth = 200
	}

	gitDir := filepath.Join(repoPath, ".git")
	if info, err := os.Stat(gitDir); err != nil || (!info.IsDir() && !strings.HasSuffix(repoPath, ".git")) {
		// Check if the directory itself is a bare git repo
		if _, err := os.Stat(filepath.Join(repoPath, "HEAD")); err != nil {
			return nil, fmt.Errorf("target path is not a valid git repository: %s", repoPath)
		}
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(timeoutCtx, "git", "-C", repoPath, "log", "-p", "--no-color", fmt.Sprintf("-n%d", maxDepth))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed opening git log pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed executing git log: %w", err)
	}

	var findings []models.Finding
	scanner := bufio.NewScanner(stdout)

	var currentCommit string
	var currentFile string
	var diffBuilder strings.Builder

	flushDiff := func() {
		if diffBuilder.Len() == 0 {
			return
		}
		diffText := diffBuilder.String()
		diffBuilder.Reset()

		matches := detectSecrets(diffText)
		for _, m := range matches {
			finding := models.Finding{
				ScanID:       scanID,
				Severity:     m.Risk,
				Confidence:   m.Confidence,
				Verification: "commit_history_audit",
				Asset:        fmt.Sprintf("%s:%s", filepath.Base(repoPath), currentFile),
				Title:        fmt.Sprintf("Secret leaked in Git history: %s", secretTitle(m.Kind)),
				Evidence:     fmt.Sprintf("Commit: %s; file: %s; redacted fingerprint: %s; structural validation=%t", currentCommit, currentFile, m.Redacted, m.Validated),
				Remediation:  "Revoke and rotate the exposed credential immediately. Rewrite git history using git-filter-repo to purge the secret from all commit objects.",
				CWE:          "CWE-798",
				CreatedAt:    time.Now().UTC(),
			}
			if e.db != nil {
				_ = e.db.AddFinding(ctx, finding)
			}
			findings = append(findings, finding)
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "commit ") {
			flushDiff()
			currentCommit = strings.TrimPrefix(line, "commit ")
			if len(currentCommit) > 12 {
				currentCommit = currentCommit[:12]
			}
		} else if strings.HasPrefix(line, "diff --git a/") {
			flushDiff()
			parts := strings.Split(line, " ")
			if len(parts) >= 3 {
				currentFile = strings.TrimPrefix(parts[2], "a/")
			}
		} else if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			diffBuilder.WriteString(line[1:])
			diffBuilder.WriteByte('\n')
		}
	}
	flushDiff()

	_ = cmd.Wait()
	return findings, scanner.Err()
}
