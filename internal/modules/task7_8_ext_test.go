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

func TestFrontendFrameworkDetector(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><script src="react.production.min.js"></script><script src="jquery.js"></script></head><body><div id="__next"></div></body></html>`))
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

	guard := scope.New([]string{"127.0.0.1", "localhost"})
	detector := NewFrontendFrameworkDetector(db, guard)

	_, err = detector.Handle(context.Background(), models.Event{
		ScanID: "test_fw",
		Type:   "url.crawled",
		Target: ts.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error in frontend framework detector: %v", err)
	}
}

func TestHTTPDirectoryEnumerationAndErrorPage(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Admin Area"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("Whitelabel Error Page - Spring Boot"))
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

	guard := scope.New([]string{"127.0.0.1", "localhost"})
	httpMod := NewHTTP(db, guard, models.HTTPConfig{
		EnableAPIDiscovery: true,
	})

	_, err = httpMod.Handle(context.Background(), models.Event{
		ScanID: "test_http_ext",
		Type:   EventHTTPURL,
		Target: ts.URL,
	})
	if err != nil {
		t.Fatalf("unexpected error in HTTP module: %v", err)
	}
}
