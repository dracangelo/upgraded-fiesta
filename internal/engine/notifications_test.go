package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func TestCompletionSubscriptionDeliversWithoutChangingScanState(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusAccepted) }))
	defer server.Close()
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "notifications.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.StartScan(ctx, "notification-scan"); err != nil {
		t.Fatal(err)
	}
	if err := db.FinishScan(ctx, "notification-scan", "completed", ""); err != nil {
		t.Fatal(err)
	}
	deliverCompletionSubscription(db, "notification-scan", models.Config{Notifications: models.NotificationConfig{EnableScanCompletedWebhook: true, WebhookURL: server.URL}})
	if calls.Load() != 1 {
		t.Fatalf("expected one completion subscription delivery, got %d", calls.Load())
	}
	status, err := db.GetScanStatus(ctx, "notification-scan")
	if err != nil || status != "completed" {
		t.Fatalf("notification must not change scan state: %q %v", status, err)
	}
}
