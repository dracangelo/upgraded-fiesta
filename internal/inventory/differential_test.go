package inventory

import (
	"strings"
	"testing"

	"enumscan/internal/models"
)

func TestFullDifferentialAnalysis(t *testing.T) {
	baseline := []models.Asset{{Type: "host", Value: "old.example"}, {Type: "open_port", Value: "old.example:443"}, {Type: "service", Value: "nginx", Parent: "old.example:443"}, {Type: "tls_certificate", Value: "old-cert", Parent: "https://old.example"}, {Type: "technology", Value: "PHP/7", Parent: "https://old.example"}}
	current := []models.Asset{{Type: "host", Value: "new.example"}, {Type: "open_port", Value: "new.example:8443"}, {Type: "service", Value: "apache", Parent: "old.example:443"}, {Type: "tls_certificate", Value: "new-cert", Parent: "https://old.example"}, {Type: "technology", Value: "PHP/8", Parent: "https://old.example"}}
	baselineFindings := []models.Finding{{CVE: "CVE-OLD", Asset: "old.example"}}
	currentFindings := []models.Finding{{CVE: "CVE-NEW", Asset: "new.example"}}
	result := NewDifferentialPortScanner().Compare(baseline, current, baselineFindings, currentFindings)
	if len(result.NewHosts) != 1 || len(result.RemovedHosts) != 1 || len(result.NewOpenPorts) != 1 || len(result.NewlyClosedPorts) != 1 || len(result.ServiceChanges) != 1 || len(result.CertificateChanges) != 1 || len(result.TechnologyChanges) != 1 || len(result.VulnerabilityChanges) != 2 {
		t.Fatalf("unexpected differential result: %#v", result)
	}
	if !strings.Contains(result.Markdown("base", "current"), "Vulnerability Changes") {
		t.Fatal("expected Markdown report")
	}
}
