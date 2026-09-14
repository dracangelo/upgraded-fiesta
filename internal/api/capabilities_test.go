package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"enumscan/internal/capability"
)

func TestCapabilitiesEndpoint(t *testing.T) {
	server := NewServer(nil, 0)
	recorder := httptest.NewRecorder()
	server.handleCapabilities(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("unexpected response: %d %s", recorder.Code, recorder.Body.String())
	}
	var manifest capability.Manifest
	if err := json.Unmarshal(recorder.Body.Bytes(), &manifest); err != nil || len(manifest.Capabilities) < 20 {
		t.Fatalf("invalid capability manifest: entries=%d err=%v", len(manifest.Capabilities), err)
	}

	recorder = httptest.NewRecorder()
	server.handleCapabilities(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/capabilities", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d", recorder.Code)
	}
}
