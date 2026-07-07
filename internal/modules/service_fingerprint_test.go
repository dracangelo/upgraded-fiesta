package modules

import "testing"

func TestRefineFromEvidenceNormalizesHTTPProducts(t *testing.T) {
	tests := []struct {
		name     string
		evidence string
		wantName string
		wantCPE  string
		wantVer  string
	}{
		{
			name:     "apache",
			evidence: "HTTP/1.1 200 OK Server: Apache/2.4.57",
			wantName: "http",
			wantCPE:  "cpe:/a:apache:http_server",
			wantVer:  "2.4.57",
		},
		{
			name:     "nginx",
			evidence: "Server: nginx/1.24.0",
			wantName: "http",
			wantCPE:  "cpe:/a:nginx:nginx",
			wantVer:  "1.24.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := refineFromEvidence(fingerprintFromPort(80, "tcp"), tt.evidence)
			if got.Name != tt.wantName || got.CPE != tt.wantCPE || got.Version != tt.wantVer {
				t.Fatalf("got name=%q cpe=%q version=%q", got.Name, got.CPE, got.Version)
			}
		})
	}
}

func TestFingerprintFromPortCoversRequiredServices(t *testing.T) {
	required := map[int]string{
		22:    "ssh",
		21:    "ftp",
		25:    "smtp",
		53:    "dns",
		445:   "smb",
		389:   "ldap",
		3306:  "mysql",
		5432:  "postgresql",
		6379:  "redis",
		9200:  "elasticsearch",
		6443:  "kubernetes-api",
		27017: "mongodb",
	}

	for port, want := range required {
		got := fingerprintFromPort(port, "tcp")
		if got.Name != want {
			t.Fatalf("port %d: got service %q, want %q", port, got.Name, want)
		}
		if got.CPE == "" {
			t.Fatalf("port %d: expected CPE candidate", port)
		}
		if got.Evidence == "" {
			t.Fatalf("port %d: expected evidence", port)
		}
	}
}
