package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestOperatorCachePersistsAndExpiresValues(t *testing.T) {
	db, err := OpenSQLiteCLI(filepath.Join(t.TempDir(), "cache.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := db.PutCachedValue(context.Background(), "rules:v1", "serialized-rules", time.Hour); err != nil {
		t.Fatal(err)
	}
	value, ok, err := db.CachedValue(context.Background(), "rules:v1")
	if err != nil || !ok || value != "serialized-rules" {
		t.Fatalf("unexpected cached value: %q, %t, %v", value, ok, err)
	}
	if err := db.PutCachedValue(context.Background(), "expired", "old", time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	if _, ok, err := db.CachedValue(context.Background(), "expired"); err != nil || ok {
		t.Fatalf("expired value was returned: %t, %v", ok, err)
	}
}
