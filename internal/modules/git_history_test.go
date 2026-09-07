package modules

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestScanGitHistoryReturnsOnlyRedactedFindings(t *testing.T) {
	repo := t.TempDir()
	for _, args := range [][]string{{"init"}, {"config", "user.email", "test@example.invalid"}, {"config", "user.name", "Enumscan test"}} {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
	}
	secret := "AKIAIOSFODNN7EXAMPLE"
	if err := os.WriteFile(filepath.Join(repo, "settings.txt"), []byte("token="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"add", "settings.txt"}, {"commit", "-m", "fixture"}} {
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
	}

	findings, err := ScanGitHistory(context.Background(), repo, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 || findings[0].Match.Kind != "aws_access_key" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
	for _, finding := range findings {
		if finding.Match.Redacted == secret || len(finding.Commit) < 8 {
			t.Fatalf("secret or commit evidence was not safely represented: %#v", finding)
		}
	}
}
