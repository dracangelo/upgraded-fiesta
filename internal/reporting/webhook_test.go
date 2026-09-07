package reporting

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestDeliverWebhookPostsBoundedEvidenceSummary(t *testing.T) {
	var received WebhookPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected webhook request: %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "webhook.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.AddAsset(ctx, models.Asset{ScanID: "scan-webhook", Type: "host", Value: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := db.AddFinding(ctx, models.Finding{ScanID: "scan-webhook", Severity: "high", Verification: "observed", Asset: "127.0.0.1:443", Title: "TLS configuration concern"}); err != nil {
		t.Fatal(err)
	}

	if err := DeliverWebhook(ctx, db, "scan-webhook", server.URL); err != nil {
		t.Fatal(err)
	}
	if received.Event != "enumscan.scan_summary" || received.ScanID != "scan-webhook" || received.AssetCount != 1 || received.FindingCount != 1 || received.Severities["high"] != 1 {
		t.Fatalf("unexpected webhook summary: %#v", received)
	}
}

func TestWebhookEndpointRequiresHTTPSOutsideLoopback(t *testing.T) {
	for _, endpoint := range []string{"", "http://example.test/hook", "ftp://example.test/hook", "https://user:pass@example.test/hook", "https://example.test/hook#fragment"} {
		if err := validateWebhookEndpoint(endpoint); err == nil {
			t.Fatalf("expected invalid webhook endpoint %q to be rejected", endpoint)
		}
	}
	if err := validateWebhookEndpoint("https://alerts.example.test/enumscan"); err != nil {
		t.Fatal(err)
	}
	if err := validateWebhookEndpoint("http://127.0.0.1:9000/enumscan"); err != nil {
		t.Fatal(err)
	}
}

func TestDeliverSlackWebhookPostsCompactSummary(t *testing.T) {
	var received SlackPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "slack.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.AddFinding(ctx, models.Finding{ScanID: "scan-slack", Severity: "medium", Title: "Header concern", Asset: "127.0.0.1:80"}); err != nil {
		t.Fatal(err)
	}
	if err := DeliverSlackWebhook(ctx, db, "scan-slack", server.URL); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(received.Text, "scan-slack") || !strings.Contains(received.Text, "1 findings") || len(received.Text) > 3600 {
		t.Fatalf("unexpected Slack payload: %#v", received)
	}
}
