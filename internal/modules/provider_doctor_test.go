package modules

import (
	"net/http"
	"strings"
	"testing"

	"enumscan/internal/models"
)

func TestDiagnosePassiveIntelIsLocalAndCredentialSafe(t *testing.T) {
	lookups := map[string]string{
		"SHODAN_API_KEY": "not-for-output",
		"FOFA_EMAIL":     "operator@example.test",
	}
	report := DiagnosePassiveIntel(models.PassiveIntelConfig{
		Enabled: true,
		Sources: []string{"FoFa", "shodan", "shodan", "unknown"},
	}, func(name string) (string, bool) {
		value, ok := lookups[name]
		return value, ok
	})

	if len(report.Providers) != 3 {
		t.Fatalf("expected deduplicated diagnostics, got %#v", report.Providers)
	}
	if got := report.Providers[0]; got.Source != "fofa" || got.Status != "not ready" || len(got.MissingEnvironment) != 1 || got.MissingEnvironment[0] != "FOFA_API_KEY" {
		t.Fatalf("unexpected FOFA diagnostic: %#v", got)
	}
	if got := report.Providers[1]; got.Source != "shodan" || got.Status != "ready to attempt" || len(got.MissingEnvironment) != 0 {
		t.Fatalf("unexpected Shodan diagnostic: %#v", got)
	}
	if got := report.Providers[2]; got.Source != "unknown" || got.Status != "unsupported" {
		t.Fatalf("unexpected unknown-provider diagnostic: %#v", got)
	}

	text := FormatPassiveIntelDoctorText(report)
	if strings.Contains(text, lookups["SHODAN_API_KEY"]) || strings.Contains(text, lookups["FOFA_EMAIL"]) {
		t.Fatalf("doctor output must not expose environment values: %q", text)
	}
	if !strings.Contains(text, "does not contact providers") {
		t.Fatalf("expected offline-preflight explanation, got %q", text)
	}
}

func TestRemoteDiagnosticHelpersAndFormatting(t *testing.T) {
	if !remoteCheckSupported("shodan") || remoteCheckSupported("bucket") {
		t.Fatal("unexpected remote diagnostic support classification")
	}
	headers := make(http.Header)
	headers.Set("X-RateLimit-Remaining", "17")
	quota := quotaFromHeaders(headers)
	if quota == nil || *quota != 17 {
		t.Fatalf("expected header-reported quota, got %#v", quota)
	}
	invalidHeaders := make(http.Header)
	invalidHeaders.Set("RateLimit-Remaining", "not-a-number")
	if unexpected := quotaFromHeaders(invalidHeaders); unexpected != nil {
		t.Fatalf("expected invalid quota header to be ignored, got %d", *unexpected)
	}
	text := FormatPassiveIntelDoctorText(PassiveIntelDoctorReport{
		RemoteDiagnosticsRequested: true,
		Providers: []ProviderDiagnostic{{
			Source:         "shodan",
			Status:         "ready to attempt",
			Mode:           "credentialed third-party API",
			RemoteStatus:   "provider reachable (HTTP 200)",
			QuotaRemaining: quota,
		}},
	})
	for _, expected := range []string{"provider reachable (HTTP 200)", "reported quota remaining: 17", "Remote diagnostics were explicitly requested"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("expected %q in formatted report: %s", expected, text)
		}
	}
}

func TestDiagnosePassiveIntelDisabledAndDirectSources(t *testing.T) {
	report := DiagnosePassiveIntel(models.PassiveIntelConfig{Sources: []string{"wayback", "bucket"}}, nil)
	if len(report.Warnings) != 1 {
		t.Fatalf("expected disabled warning, got %#v", report.Warnings)
	}
	for _, provider := range report.Providers {
		if provider.Status != "disabled" || provider.Enabled {
			t.Fatalf("expected disabled direct-source diagnostic, got %#v", provider)
		}
	}
}
