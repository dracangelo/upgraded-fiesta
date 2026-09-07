package plugin

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestTrustedMarketplaceSearchRatingsVersionsInstallAndVerification(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry("http://127.0.0.1", private)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(registry)
	defer server.Close()
	registry.baseURL = server.URL
	manifest := PluginManifest{Name: "Community Headers", Version: "1.0.0", Author: "community", Description: "header inventory", Type: "lua", Exec: "main.lua", Permissions: []string{PermissionStoreWrite}, Subscriptions: []string{"http.url"}}
	if err := registry.Publish("community.headers", manifest, map[string][]byte{"main.lua": []byte(`add_asset("header_check", event.target)`)}, []string{"http", "community"}, true); err != nil {
		t.Fatal(err)
	}
	manifest.Version = "1.1.0"
	if err := registry.Publish("community.headers", manifest, map[string][]byte{"main.lua": []byte(`add_asset("header_check_v2", event.target)`)}, []string{"http", "community"}, true); err != nil {
		t.Fatal(err)
	}

	installRoot := t.TempDir()
	manager := NewTrustedMarketplaceManager(server.URL, public, installRoot)
	plugins, err := manager.SearchPlugins(context.Background(), "headers")
	if err != nil || len(plugins) != 1 || plugins[0].Version != "1.1.0" || !plugins[0].Community {
		t.Fatalf("unexpected discovery: %#v, %v", plugins, err)
	}
	if err := manager.RatePlugin(context.Background(), "community.headers", 5); err != nil {
		t.Fatal(err)
	}
	detail, err := manager.GetPlugin(context.Background(), "community.headers")
	if err != nil || detail.Rating != 5 || detail.RatingCount != 1 || len(detail.Versions) != 2 {
		t.Fatalf("unexpected marketplace detail: %#v, %v", detail, err)
	}
	installed, err := manager.Install(context.Background(), "community.headers", "1.0.0")
	if err != nil || !strings.HasSuffix(installed, filepath.Join("community.headers", "1.0.0")) {
		t.Fatalf("install failed: %q, %v", installed, err)
	}
	pluginManager, _ := NewManager(nil, scope.New(nil), "")
	if err := pluginManager.LoadInstalled(installRoot, "community.headers", public); err != nil {
		t.Fatalf("activate verified plugin: %v", err)
	}
	if len(pluginManager.manifests) != 1 {
		t.Fatal("verified plugin was not explicitly activated")
	}
	if err := os.WriteFile(filepath.Join(installed, "main.lua"), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := pluginManager.LoadInstalled(installRoot, "community.headers", public); err == nil {
		t.Fatal("tampered installed plugin was accepted")
	}
}

func TestMarketplaceRejectsWrongTrustRoot(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(nil)
	wrongPublic, _, _ := ed25519.GenerateKey(nil)
	registry, _ := NewRegistry("http://127.0.0.1", private)
	server := httptest.NewServer(registry)
	defer server.Close()
	registry.baseURL = server.URL
	manifest := PluginManifest{Name: "Signed", Version: "1.0.0", Type: "lua", Exec: "main.lua", Subscriptions: []string{"*"}}
	_ = registry.Publish("signed", manifest, map[string][]byte{"main.lua": []byte("return")}, nil, false)
	manager := NewTrustedMarketplaceManager(server.URL, wrongPublic, t.TempDir())
	if _, err := manager.Install(context.Background(), "signed", ""); err == nil {
		t.Fatal("package signed by an untrusted key was installed")
	}
}

type testPluginService interface{}

func TestRealGRPCPluginRuntime(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "enumscan.plugin.v1.Plugin",
		HandlerType: (*testPluginService)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Execute", Handler: func(_ any, ctx context.Context, decode func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
			request := &structpb.Struct{}
			if err := decode(request); err != nil {
				return nil, err
			}
			return structpb.NewStruct(map[string]any{"assets": []any{map[string]any{"type": "grpc_observation", "value": "observed"}}})
		}}},
		Metadata: "enumscan-plugin-v1",
	}, struct{}{})
	go server.Serve(listener)
	defer server.Stop()

	manifest := &PluginManifest{Name: "grpc-test", Version: "1.0.0", Type: "grpc", Exec: "grpc://" + listener.Addr().String(), Permissions: []string{PermissionStoreWrite}, Subscriptions: []string{"host.discovered"}}
	result, err := NewGRPCHost(manifest).Execute(context.Background(), models.Event{ScanID: "scan", Type: "host.discovered", Target: "127.0.0.1"})
	if err != nil || len(result.Assets) != 1 || result.Assets[0].ScanID != "scan" {
		t.Fatalf("unexpected gRPC result: %#v, %v", result, err)
	}
	manifest.Exec = "grpc://example.com:443"
	if _, err := NewGRPCHost(manifest).Execute(context.Background(), models.Event{}); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("plaintext remote gRPC endpoint was not rejected: %v", err)
	}
}

func TestLuaRuntimeDoesNotExposeOSLibrary(t *testing.T) {
	script := filepath.Join(t.TempDir(), "sandbox.lua")
	if err := os.WriteFile(script, []byte(`if os ~= nil then error("os exposed") end; add_event("plugin.complete")`), 0600); err != nil {
		t.Fatal(err)
	}
	manifest := &PluginManifest{Name: "lua-sandbox", Version: "1.0.0", Type: "lua", Exec: script, Subscriptions: []string{"*"}}
	result, err := NewLuaRunner(manifest).Execute(context.Background(), models.Event{ScanID: "scan", Target: "example.test"})
	if err != nil || len(result.Events) != 1 {
		t.Fatalf("real Lua execution failed: %#v, %v", result, err)
	}
}
