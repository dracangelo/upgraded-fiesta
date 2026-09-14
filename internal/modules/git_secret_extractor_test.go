package modules

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestGitSecretExtractor(t *testing.T) {
	tempDir := t.TempDir()
	repoDir := filepath.Join(tempDir, "test-repo")
	if err := os.MkdirAll(repoDir, 0750); err != nil {
		t.Fatal(err)
	}

	// Initialize git repo
	runGit := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %s (%v)", args, string(out), err)
		}
	}

	runGit("init")
	runGit("config", "user.name", "Security Auditor")
	runGit("config", "user.email", "auditor@example.internal")

	// Commit 1: clean file
	readmeFile := filepath.Join(repoDir, "README.md")
	_ = os.WriteFile(readmeFile, []byte("# Internal Repo\nSafe docs"), 0600)
	runGit("add", "README.md")
	runGit("commit", "-m", "Initial commit")

	// Commit 2: introduce leaked AWS key
	configEnv := filepath.Join(repoDir, ".env")
	_ = os.WriteFile(configEnv, []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nDATABASE_URL=postgres://localhost\n"), 0600)
	runGit("add", ".env")
	runGit("commit", "-m", "Add local env config")

	// Commit 3: commit private key
	keyFile := filepath.Join(repoDir, "server.key")
	_ = os.WriteFile(keyFile, []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----\n"), 0600)
	runGit("add", "server.key")
	runGit("commit", "-m", "Add test ssl key")

	db, err := store.OpenSQLiteCLI(filepath.Join(tempDir, "git.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	ctx := context.Background()
	_ = db.Migrate(ctx)

	guard := scope.New([]string{"127.0.0.1"})
	extractor := NewGitSecretExtractor(db, guard, 10)

	findings, err := extractor.ScanRepositoryHistory(ctx, "scan-git-1", repoDir, 10)
	if err != nil {
		t.Fatalf("ScanRepositoryHistory failed: %v", err)
	}

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 leaked secret findings, got %d", len(findings))
	}

	for _, f := range findings {
		// Strict check: raw secret must NEVER appear in finding or evidence
		if strings.Contains(f.Evidence, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("raw AWS secret key leaked into evidence: %s", f.Evidence)
		}
		if !strings.Contains(f.Evidence, "redacted fingerprint") {
			t.Errorf("expected redacted fingerprint in evidence: %s", f.Evidence)
		}
	}
}
