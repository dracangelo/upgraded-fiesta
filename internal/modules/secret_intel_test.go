package modules

import "testing"

func TestDetectSecretsClassifiesAndRedacts(t *testing.T) {
	body := `
aws=AKIAIOSFODNN7EXAMPLE
DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=abcdefghijklmnopqrstuvwxyz0123456789+/==
gcp=AIzaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
jwt_secret="a-very-long-development-signing-secret"
-----BEGIN PRIVATE KEY-----
`
	matches := detectSecrets(body)
	got := make(map[string]SecretMatch)
	for _, match := range matches {
		got[match.Kind] = match
	}
	for _, kind := range []string{"aws_access_key", "azure_storage_connection", "gcp_api_key", "jwt_secret", "private_key"} {
		match, ok := got[kind]
		if !ok {
			t.Errorf("missing %s in %#v", kind, got)
			continue
		}
		if match.Redacted == "" || match.Redacted == body {
			t.Errorf("%s was not redacted", kind)
		}
	}
	if got["private_key"].Risk != "critical" {
		t.Fatal("private key should be critical")
	}
}

func TestSecretValidationHelpers(t *testing.T) {
	if !validAWSAccessKey("AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("expected valid AWS access key shape")
	}
	if validAWSAccessKey("AKIAshort") {
		t.Fatal("short AWS key must fail validation")
	}
}
