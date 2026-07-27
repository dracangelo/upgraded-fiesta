package modules

import "testing"

func TestContainerChecksCoverTaskTenEndpoints(t *testing.T) {
	cases := []struct {
		port int
		kind string
	}{
		{2375, "docker_socket"},
		{5000, "registry"},
		{2375, "runtime"},
		{2375, "compose"},
		{6443, "kubernetes_secrets"},
	}
	for _, tc := range cases {
		found := false
		for _, check := range containerChecks(tc.port, "") {
			if check.kind == tc.kind {
				found = true
			}
		}
		if !found {
			t.Errorf("port %d missing %s check", tc.port, tc.kind)
		}
	}
}

func TestKubernetesItemCountAndRegistryResponse(t *testing.T) {
	if got := kubernetesItemCount([]byte(`{"items":[{},{}]}`)); got != 2 {
		t.Fatalf("got %d items", got)
	}
	if !(containerCheck{kind: "registry"}).accepts(401) {
		t.Fatal("authenticated registry response should identify a registry")
	}
	if !isComposeDocument([]byte("version: '3'\nservices:\n  app:\n    image: example/app")) {
		t.Fatal("expected compose document detection")
	}
	if isComposeDocument([]byte("<html><body>services: unavailable</body></html>")) {
		t.Fatal("ordinary HTML must not be treated as a compose document")
	}
}
