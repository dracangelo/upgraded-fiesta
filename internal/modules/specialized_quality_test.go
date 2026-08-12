package modules

import (
	"bufio"
	"encoding/binary"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestLDAPRootDSERequestAndNamingContexts(t *testing.T) {
	request := ldapRootDSERequest()
	if len(request) < 4 || request[0] != 0x30 || int(request[1])+2 != len(request) {
		t.Fatalf("invalid LDAP message framing: %x", request)
	}
	if !containsBytes(request, []byte("namingContexts")) || !containsBytes(request, []byte("defaultNamingContext")) {
		t.Fatalf("RootDSE request omitted requested attributes: %x", request)
	}
	got := ldapNamingContexts("namingContexts\x00DC=Example,DC=Test\x00dc=example,dc=test\x00DC=other,DC=test")
	want := []string{"dc=example,dc=test", "dc=other,dc=test"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("naming contexts = %#v, want %#v", got, want)
	}
}

func TestReadSSHKEXAlgorithms(t *testing.T) {
	payload := append([]byte{20}, make([]byte, 16)...)
	for _, list := range []string{"curve25519-sha256,diffie-hellman-group14-sha256", "ssh-ed25519,rsa-sha2-512"} {
		value := []byte(list)
		length := make([]byte, 4)
		binary.BigEndian.PutUint32(length, uint32(len(value)))
		payload = append(payload, length...)
		payload = append(payload, value...)
	}
	packetLength := len(payload) + 5
	packet := make([]byte, 5)
	binary.BigEndian.PutUint32(packet[:4], uint32(packetLength))
	packet[4] = 4
	packet = append(packet, payload...)
	packet = append(packet, []byte{0, 0, 0, 0}...)
	got := readSSHKEXAlgorithms(bufio.NewReader(strings.NewReader(string(packet))))
	want := []string{"curve25519-sha256,diffie-hellman-group14-sha256", "ssh-ed25519,rsa-sha2-512"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("algorithms = %#v, want %#v", got, want)
	}
}

func TestProtocolEnumerationPortSelection(t *testing.T) {
	for _, port := range []int{21, 22, 25, 587} {
		if !isProtocolEnumerationPort(port, "") {
			t.Fatalf("port %d should be selected", port)
		}
	}
	if isProtocolEnumerationPort(80, "http") {
		t.Fatal("HTTP must not use the plaintext protocol enumerator")
	}
}

func TestSNMPEvidenceHelpers(t *testing.T) {
	for _, community := range []string{"public", "PRIVATE", " community "} {
		if !isDefaultSNMPCommunity(community) {
			t.Fatalf("%q should be recognised as a default community", community)
		}
	}
	if isDefaultSNMPCommunity("assessment-readonly") {
		t.Fatal("custom SNMP community reported as default")
	}
	if got := snmpSystemDescription([]byte("\x30\x01public\x00Linux router 6.1")); got != "Linux router 6.1" {
		t.Fatalf("sysDescr = %q", got)
	}
}

func TestDetectServerlessHeaders(t *testing.T) {
	tests := []struct {
		headers http.Header
		vendor  string
		kind    string
	}{
		{http.Header{"X-Amz-Executed-Version": []string{"12"}}, "aws", "lambda"},
		{http.Header{"X-Azure-Functions-Version": []string{"4"}}, "azure", "functions"},
		{http.Header{"X-Cloud-Trace-Context": []string{"trace"}, "X-Cloud-Run-Region": []string{"us-central1"}}, "gcp", "cloud_functions_or_run"},
		{http.Header{"Server": []string{"nginx"}}, "", ""},
	}
	for _, tt := range tests {
		vendor, kind := detectServerlessHeaders(tt.headers)
		if vendor != tt.vendor || kind != tt.kind {
			t.Errorf("detectServerlessHeaders(%v) = (%q, %q), want (%q, %q)", tt.headers, vendor, kind, tt.vendor, tt.kind)
		}
	}
}

func containsBytes(haystack, needle []byte) bool {
	for start := 0; start+len(needle) <= len(haystack); start++ {
		if string(haystack[start:start+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
