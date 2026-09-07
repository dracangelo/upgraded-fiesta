package modules

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"enumscan/internal/models"
)

func TestProviderControlsOverrideSourceSelection(t *testing.T) {
	cfg := models.PassiveIntelConfig{Sources: []string{"shodan", "github"}, ProviderControls: []string{"shodan=false", "gitlab=true"}}
	if got, want := effectiveProviderSources(cfg), []string{"github", "gitlab"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("effective providers=%v want=%v", got, want)
	}
	report := DiagnosePassiveIntel(cfg, func(name string) (string, bool) { return "credential", true })
	statuses := map[string]string{}
	for _, provider := range report.Providers {
		statuses[provider.Source] = provider.Status
	}
	if statuses["shodan"] != "disabled" || statuses["gitlab"] != "disabled" { // global switch remains authoritative
		t.Fatalf("global disable was not preserved: %#v", statuses)
	}
}

func TestStructuredProviderQuotaAndUpdateSignals(t *testing.T) {
	reset := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	header := make(http.Header)
	header.Set("X-RateLimit-Limit", "5000")
	header.Set("X-RateLimit-Remaining", "4990")
	header.Set("X-RateLimit-Used", "10")
	header.Set("X-RateLimit-Reset", reset.Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	header.Set("X-RateLimit-Resource", "core")
	quota := quotaFromResponse("github", header, nil)
	if quota == nil || quota.Limit == nil || *quota.Limit != 5000 || quota.Remaining == nil || *quota.Remaining != 4990 || quota.Used == nil || *quota.Used != 10 || quota.Resource != "core" || quota.ResetAt == "" {
		t.Fatalf("incomplete structured quota: %#v", quota)
	}
	shodan := quotaFromResponse("shodan", nil, []byte(`{"credits":23}`))
	if shodan == nil || shodan.Remaining == nil || *shodan.Remaining != 23 || shodan.Source != "response body" {
		t.Fatalf("Shodan body quota not parsed: %#v", shodan)
	}
	definition, _ := passiveProviderDefinition("github")
	cfg := models.PassiveIntelConfig{EnableUpdateChecks: true, ProviderVersions: []string{"github=2022-11-28"}}
	header.Set("X-GitHub-Api-Version-Selected", "2026-03-10")
	if status := providerUpdateStatus(cfg, "github", definition, header); status != "update available: configured=2022-11-28 provider=2026-03-10" {
		t.Fatalf("unexpected update status %q", status)
	}
	header.Set("Sunset", "Wed, 01 Jan 2027 00:00:00 GMT")
	if status := providerUpdateStatus(cfg, "github", definition, header); !strings.HasPrefix(status, "update required:") {
		t.Fatalf("sunset was not surfaced: %q", status)
	}
}

func TestProviderSpecificCredentialShapeValidation(t *testing.T) {
	lookup := func(name string) (string, bool) {
		values := map[string]string{"FOFA_EMAIL": "not-an-email", "FOFA_API_KEY": "key"}
		value, ok := values[name]
		return value, ok
	}
	if validProviderCredentialShape("fofa", lookup) {
		t.Fatal("invalid FOFA account email accepted")
	}
	lookup = func(name string) (string, bool) { return "token\nsmuggled", true }
	if validProviderCredentialShape("github", lookup) {
		t.Fatal("multi-line provider credential accepted")
	}
}
