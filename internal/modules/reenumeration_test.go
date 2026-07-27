package modules

import (
	"context"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/scope"
)

func TestReenumerationFollowsScopedChange(t *testing.T) {
	m := NewReenumeration(scope.New([]string{"example.test"}))
	next, err := m.Handle(context.Background(), models.Event{ScanID: "s", Type: EventAssetChanged, Target: "https://api.example.test/v1", Data: map[string]string{"kind": "url"}})
	if err != nil || len(next) != 1 || next[0].Type != EventHTTPURL {
		t.Fatalf("unexpected result %#v err=%v", next, err)
	}
	next, _ = m.Handle(context.Background(), models.Event{ScanID: "s", Type: EventAssetChanged, Target: "outside.test:443", Data: map[string]string{"kind": "port"}})
	if len(next) != 0 {
		t.Fatalf("outside-scope event should be ignored: %#v", next)
	}
}
