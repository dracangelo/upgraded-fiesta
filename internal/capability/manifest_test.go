package capability

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestManifestIsUniqueSortedAndSerializable(t *testing.T) {
	manifest := Current()
	if manifest.SchemaVersion == "" || len(manifest.Capabilities) < 20 {
		t.Fatalf("incomplete manifest: %#v", manifest)
	}
	seen := make(map[string]bool)
	previous := ""
	for _, entry := range manifest.Capabilities {
		if entry.ID == "" || entry.Name == "" || entry.Category == "" || entry.Summary == "" || len(entry.Platforms) == 0 {
			t.Fatalf("incomplete capability: %#v", entry)
		}
		if seen[entry.ID] || entry.ID < previous {
			t.Fatalf("capabilities must have unique sorted IDs: %q", entry.ID)
		}
		seen[entry.ID], previous = true, entry.ID
		switch entry.Status {
		case Implemented, Experimental, Gated, Planned, IntentionallyExcluded:
		default:
			t.Fatalf("invalid status %q", entry.Status)
		}
	}
	payload, err := JSON()
	if err != nil || !json.Valid(payload) {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !strings.Contains(Markdown(), "| `postgres` |") || !strings.Contains(Text(), "plugin-os-sandbox") {
		t.Fatal("renderers omitted known capabilities")
	}
}
