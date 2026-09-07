package reporting

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestWriteLocalLLMAdvisoryUsesLoopbackOllamaOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/generate" {
			t.Fatalf("unexpected local LLM request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"response":"Review the observed evidence with the asset owner."}`))
	}))
	defer server.Close()
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "llm.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.AddFinding(ctx, models.Finding{ScanID: "scan-llm", Severity: "medium", Verification: "heuristic", Title: "Observed header", Asset: "127.0.0.1:80"}); err != nil {
		t.Fatal(err)
	}
	path, err := WriteLocalLLMAdvisory(ctx, db, "scan-llm", models.ReportingConfig{OutputDir: t.TempDir(), LocalLLMURL: server.URL + "/api/generate", LocalLLMModel: "test-model", LocalLLMTimeoutMS: 1000})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(content), "not independently verified") || !strings.Contains(string(content), "asset owner") {
		t.Fatalf("unexpected advisory: %q, %v", content, err)
	}
}

func TestLocalLLMEndpointRejectsNonLoopback(t *testing.T) {
	if _, err := validateLocalLLMEndpoint("http://example.test/api/generate"); err == nil {
		t.Fatal("expected non-loopback local LLM endpoint rejection")
	}
}
