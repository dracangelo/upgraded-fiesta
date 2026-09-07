package modules

import "testing"

func TestTask27IntegrationsFramework(t *testing.T) {
	provider, ok := passiveProviderDefinition("urlscan")
	if !ok || provider.Name != "urlscan" || !provider.RemoteProbe {
		t.Fatalf("expected concrete urlscan provider definition, got %#v", provider)
	}
	if _, ok := passiveProviderDefinition("not-a-provider"); ok {
		t.Fatal("unknown providers must not be represented as configured integrations")
	}
	if !passiveProviderCatalog["abuseipdb"].IPOnly {
		t.Fatal("AbuseIPDB integration must remain limited to documented IP lookups")
	}
}
