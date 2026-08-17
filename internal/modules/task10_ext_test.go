package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestTask10SpecializedProbes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"imds": "active"}`))
	}))
	defer ts.Close()

	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	guard := scope.New([]string{"127.0.0.1", "localhost", "example.com"})
	spec := NewSpecialized(db, guard, models.SpecializedConfig{
		EnableCloud:               true,
		EnableSMB:                 true,
		EnableLDAP:                true,
		EnableSNMP:                true,
		EnableContainer:           true,
		EnableDatabase:            true,
		EnableProtocolEnumeration: true,
	})

	// Test EventTarget triggers DNS & IMDS
	_, err = spec.Handle(context.Background(), models.Event{
		ScanID: "test_spec_10",
		Type:   EventTarget,
		Target: "example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error in Specialized module: %v", err)
	}
}
