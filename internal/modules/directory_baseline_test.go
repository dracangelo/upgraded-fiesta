package modules

import "testing"

func TestDirectoryBaselineSuppressesWildcardResponses(t *testing.T) {
	baseline := directoryBaseline{status: 200, length: 42, body: "not found <dynamic>"}
	if !baseline.matches(200, "not found /missing/abcdef0123456789") {
		t.Fatal("equivalent wildcard response was not suppressed")
	}
	if baseline.matches(200, "actual administration portal") || baseline.matches(404, "not found") {
		t.Fatal("distinct directory response was incorrectly suppressed")
	}
}
