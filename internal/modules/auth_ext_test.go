package modules

import (
	"context"
	"path/filepath"
	"testing"

	"enumscan/internal/scope"
	"enumscan/internal/store"
)

func TestAuthProtocolAndSessionJWTScanners(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "test.sqlite"))
	if err != nil {
		t.Fatalf("OpenSQLiteCLI: %v", err)
	}
	_ = db.Migrate(context.Background())
	guard := scope.New([]string{"example.com", "127.0.0.1"})

	authMod := NewAuthProtocolScanner(db, guard)
	if authMod.Name() != "auth_protocol_scanner" {
		t.Errorf("unexpected name: %s", authMod.Name())
	}

	sessMod := NewSessionJWTScanner(db, guard)
	if sessMod.Name() != "session_jwt_scanner" {
		t.Errorf("unexpected name: %s", sessMod.Name())
	}

	alg := sessMod.extractJWTAlg("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature")
	if alg != "RS256" {
		t.Errorf("expected RS256 alg, got %s", alg)
	}

	policyMod := NewAuthPoliciesDetector(db, guard)
	if policyMod.Name() != "auth_policies_detector" {
		t.Errorf("unexpected name: %s", policyMod.Name())
	}
}
