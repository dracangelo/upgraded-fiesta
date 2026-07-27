package engine

import (
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/modules"
)

func TestReenumerationPlannerTargetsChangedEvidence(t *testing.T) {
	planner := ReenumerationPlanner{}
	got := planner.Plan(models.Event{ScanID: "s", Type: "asset.changed", Target: "https://example.test", Data: map[string]string{"kind": "certificate"}})
	if len(got) != 1 || got[0].Type != modules.EventHTTPURL {
		t.Fatalf("unexpected URL follow-up: %#v", got)
	}
	got = planner.Plan(models.Event{ScanID: "s", Type: "asset.changed", Target: "10.0.0.2:443", Data: map[string]string{"kind": "port"}})
	if len(got) != 1 || got[0].Type != modules.EventHost || got[0].Target != "10.0.0.2" {
		t.Fatalf("unexpected host follow-up: %#v", got)
	}
}
