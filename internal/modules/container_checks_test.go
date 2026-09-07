package modules

import (
	"encoding/binary"
	"testing"
)

func TestContainerChecksCoverSafeTaskTenEndpoints(t *testing.T) {
	cases := []struct {
		port int
		kind string
	}{
		{2375, "docker_socket"},
		{5000, "registry"},
		{2375, "runtime"},
		{8080, "podman"},
		{10010, "containerd"},
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
	for _, tc := range []struct {
		port int
		kind string
	}{{2375, "compose"}, {6443, "kubernetes_secrets"}} {
		for _, check := range containerChecks(tc.port, "") {
			if check.kind == tc.kind {
				t.Errorf("port %d must not request secret-bearing %s resources", tc.port, tc.kind)
			}
		}
	}
}

func TestExtendedDatabasePorts(t *testing.T) {
	for _, port := range []int{8123, 9000, 9042, 8086} {
		if !isDatabasePort(port, "") {
			t.Fatalf("port %d should be recognized as a database endpoint", port)
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

func TestObservedJSONVersionAndCassandraCapabilities(t *testing.T) {
	if got := observedJSONVersion([]byte(`{"Version":{"Version":"5.3.0"}}`)); got != "5.3.0" {
		t.Fatalf("expected nested runtime version, got %q", got)
	}
	if got := observedJSONVersion([]byte(`{"status":"pass","version":"2.7.8"}`)); got != "2.7.8" {
		t.Fatalf("expected health response version, got %q", got)
	}
	if got := observedJSONVersion([]byte(`not json`)); got != "" {
		t.Fatalf("invalid JSON must not create a version, got %q", got)
	}

	payload := cassandraCapabilitiesPayload(map[string][]string{
		"CQL_VERSION":       {"3.4.7"},
		"PROTOCOL_VERSIONS": {"3/v3", "4/v4"},
	})
	capabilities := cassandraSupportedCapabilities(payload)
	if capabilities["CQL_VERSION"] != "3.4.7" || capabilities["PROTOCOL_VERSIONS"] != "3/v3,4/v4" {
		t.Fatalf("unexpected Cassandra capabilities: %#v", capabilities)
	}
}

func cassandraCapabilitiesPayload(values map[string][]string) []byte {
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, uint16(len(values)))
	for name, entries := range values {
		payload = appendCassandraString(payload, name)
		count := make([]byte, 2)
		binary.BigEndian.PutUint16(count, uint16(len(entries)))
		payload = append(payload, count...)
		for _, entry := range entries {
			payload = appendCassandraString(payload, entry)
		}
	}
	return payload
}

func appendCassandraString(payload []byte, value string) []byte {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(value)))
	return append(append(payload, length...), value...)
}
