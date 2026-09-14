package modules

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestExternalDirectoryToolWrapper(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "dir.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	ctx := context.Background()
	_ = db.Migrate(ctx)

	// Mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin", "/login":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	parsed, _ := url.Parse(server.URL)
	guard := scope.New([]string{parsed.Hostname(), "127.0.0.1"})

	wrapper := NewExternalDirectoryToolWrapper(db, guard)

	// 1. Unapproved tool rejection
	_, err = wrapper.ExecuteScopedDirectoryScan(ctx, "scan-dir-1", server.URL, "unapproved-fuzzer", "")
	if !errors.Is(err, ErrToolNotApproved) {
		t.Fatalf("expected ErrToolNotApproved, got: %v", err)
	}

	// 2. Out-of-scope target rejection
	_, err = wrapper.ExecuteScopedDirectoryScan(ctx, "scan-dir-1", "http://unauthorized.target.com", "gobuster", "")
	if !errors.Is(err, ErrTargetOutOfScope) {
		t.Fatalf("expected ErrTargetOutOfScope, got: %v", err)
	}

	// 3. Wordlist limit enforcement
	largeWordlist := filepath.Join(t.TempDir(), "large.txt")
	var lines []string
	for i := 0; i < 150; i++ {
		lines = append(lines, "word")
	}
	_ = os.WriteFile(largeWordlist, []byte(strings.Join(lines, "\n")), 0600)

	_, err = wrapper.ExecuteScopedDirectoryScan(ctx, "scan-dir-1", server.URL, "gobuster", largeWordlist)
	if !errors.Is(err, ErrWordlistLimitLimit) {
		t.Fatalf("expected ErrWordlistLimitLimit, got: %v", err)
	}

	// 4. Successful execution with default wordlist
	assets, err := wrapper.ExecuteScopedDirectoryScan(ctx, "scan-dir-1", server.URL, "gobuster", "")
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}
	if len(assets) == 0 {
		t.Fatalf("expected discovered directory paths, got 0")
	}

	// Verify provenance metadata
	for _, a := range assets {
		if !strings.Contains(a.Metadata, "provenance=external_wrapper;tool=gobuster") {
			t.Errorf("asset missing provenance: %+v", a)
		}
	}
}
