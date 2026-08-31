package reporting

import (
	"strings"
	"testing"
)

func TestSecretRedaction(t *testing.T) {
	sampleReport := "Found AWS Key AKIAIOSFODNN7EXAMPLE and Bearer token: eyJhbGciOiJIUzI1NiJ9.test"
	redacted := RedactSecrets(sampleReport)
	if strings.Contains(redacted, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("redaction failed to mask AWS key")
	}
	if !strings.Contains(redacted, "[REDACTED_AWS_KEY]") {
		t.Fatalf("redaction failed to insert key placeholder")
	}
}
