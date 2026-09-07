package modules

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestGRPCReflectionEnumeratorListsOnlyAdvertisedServices(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := grpc.NewServer()
	reflection.Register(server)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()

	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "grpc.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port := 0
	if _, err := fmt.Sscanf(portText, "%d", &port); err != nil {
		t.Fatal(err)
	}
	module := NewGRPCReflectionEnumerator(db, scope.New([]string{"127.0.0.1"}), models.HTTPConfig{EnableGRPCReflection: true, GRPCReflectionPorts: []int{port}})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := module.Handle(ctx, models.Event{ScanID: "grpc", Type: EventPort, Target: listener.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	assets, err := db.Assets(context.Background(), "grpc")
	if err != nil || len(assets) == 0 {
		t.Fatalf("expected reflected services, got %#v, %v", assets, err)
	}
}
