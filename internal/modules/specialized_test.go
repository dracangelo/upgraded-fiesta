package modules

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func setupTestStore(t *testing.T) *store.SQLiteCLI {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.sqlite")
	st, err := store.OpenSQLiteCLI(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	ctx := context.Background()
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return st
}

func TestSpecializedModuleMetadata(t *testing.T) {
	st := setupTestStore(t)
	guard := scope.New([]string{"127.0.0.1", "localhost"})
	cfg := models.SpecializedConfig{
		EnableSMB:       true,
		EnableLDAP:      true,
		EnableSNMP:      true,
		EnableCloud:     true,
		EnableContainer: true,
		EnableDatabase:  true,
		SNMPCommunities: []string{"public"},
	}

	mod := NewSpecialized(st, guard, cfg)
	if mod.Name() != "specialized" {
		t.Errorf("expected name 'specialized', got '%s'", mod.Name())
	}

	subs := mod.Subscriptions()
	if len(subs) == 0 {
		t.Errorf("expected non-empty subscriptions")
	}
}

func TestCloudHelpers(t *testing.T) {
	vendor, details := detectCloudVendor("testbucket.s3.amazonaws.com")
	if vendor != "aws" {
		t.Errorf("expected vendor aws, got %s (%s)", vendor, details)
	}

	vendor, _ = detectCloudVendor("my-app.azurewebsites.net")
	if vendor != "azure" {
		t.Errorf("expected vendor azure, got %s", vendor)
	}

	name := sanitizeBucketName("www.my-company-test.com")
	if name != "my-company-test" {
		t.Errorf("expected 'my-company-test', got '%s'", name)
	}
}

func TestProbeRedisDatabase(t *testing.T) {
	st := setupTestStore(t)
	guard := scope.New([]string{"127.0.0.1", "localhost", "127.0.0.1:0"})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen TCP: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 128)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("$100\r\n# Server\r\nredis_version:7.0.0\r\n"))
	}()

	cfg := models.SpecializedConfig{EnableDatabase: true}
	mod := NewSpecialized(st, guard, cfg)

	evt := models.Event{
		ScanID: "test-scan-redis",
		Type:   EventPort,
		Target: ln.Addr().String(),
		Data:   map[string]string{"service": "redis", "protocol": "tcp"},
	}

	ctx := context.Background()
	evts, err := mod.Handle(ctx, evt)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if len(evts) == 0 {
		t.Fatalf("expected discovered event for Redis")
	}

	assets, err := st.Assets(ctx, "test-scan-redis")
	if err != nil || len(assets) == 0 {
		t.Errorf("expected assets recorded for Redis")
	}

	findings, err := st.Findings(ctx, "test-scan-redis")
	if err != nil || len(findings) == 0 {
		t.Errorf("expected finding recorded for Redis unauthenticated exposure")
	}
}

func TestProbeElasticsearch(t *testing.T) {
	st := setupTestStore(t)
	guard := scope.New([]string{"127.0.0.1", "localhost"})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{ "name" : "node-1", "cluster_name" : "es-cluster", "tagline" : "You Know, for Search" }`))
	}))
	defer ts.Close()

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	cfg := models.SpecializedConfig{EnableDatabase: true}
	mod := NewSpecialized(st, guard, cfg)

	evt := models.Event{
		ScanID: "test-scan-es",
		Type:   EventPort,
		Target: fmt.Sprintf("%s:%d", host, port),
		Data:   map[string]string{"service": "elasticsearch", "protocol": "tcp"},
	}

	ctx := context.Background()
	evts, err := mod.Handle(ctx, evt)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if len(evts) == 0 {
		t.Fatalf("expected discovered event for Elasticsearch")
	}
}

func TestProbeContainer(t *testing.T) {
	st := setupTestStore(t)
	guard := scope.New([]string{"127.0.0.1", "localhost"})

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/version" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Version": "24.0.5", "ApiVersion": "1.43"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()

	host, portStr, _ := net.SplitHostPort(ts.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	cfg := models.SpecializedConfig{EnableContainer: true}
	mod := NewSpecialized(st, guard, cfg)

	evt := models.Event{
		ScanID: "test-scan-docker",
		Type:   EventPort,
		Target: fmt.Sprintf("%s:%d", host, port),
		Data:   map[string]string{"service": "docker", "protocol": "tcp"},
	}

	ctx := context.Background()
	evts, err := mod.Handle(ctx, evt)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if len(evts) == 0 {
		t.Fatalf("expected container exposure event")
	}

	findings, err := st.Findings(ctx, "test-scan-docker")
	if err != nil || len(findings) == 0 {
		t.Errorf("expected finding recorded for Docker API exposure")
	}
}
