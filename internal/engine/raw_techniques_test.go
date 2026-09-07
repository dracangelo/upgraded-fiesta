package engine

import (
	"testing"

	"enumscan/internal/modules"
)

func TestAuthorizedRawTechniques(t *testing.T) {
	techniques, err := authorizedRawTechniques([]string{"syn", "ACK", "syn"})
	if err != nil {
		t.Fatal(err)
	}
	if len(techniques) != 2 || techniques[0] != modules.ScanSYN || techniques[1] != modules.ScanACK {
		t.Fatalf("unexpected techniques: %#v", techniques)
	}
	if _, err := authorizedRawTechniques([]string{"decoy"}); err == nil {
		t.Fatal("expected decoy scanning to be rejected")
	}
}
