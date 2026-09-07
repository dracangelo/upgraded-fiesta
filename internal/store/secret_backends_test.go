package store

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProductionHTTPSecretBackendsReadWriteAndRotate(t *testing.T) {
	t.Setenv("TEST_SECRET_TOKEN", "workload-token")
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-access-key")
	providers := []ProviderType{ProviderVault, ProviderK8s, ProviderAWS, ProviderAzure, ProviderGCP}
	for _, provider := range providers {
		t.Run(string(provider), func(t *testing.T) {
			value := "initial"
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if provider != ProviderAWS && r.Header.Get("Authorization") != "Bearer workload-token" && r.Header.Get("X-Vault-Token") != "workload-token" {
					t.Errorf("request did not carry configured workload credential")
				}
				if provider == ProviderAWS && (!strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || r.Header.Get("X-Amz-Date") == "") {
					t.Errorf("AWS request was not SigV4 authenticated")
				}
				switch provider {
				case ProviderVault:
					if r.Method == http.MethodPost {
						var body struct {
							Data map[string]string `json:"data"`
						}
						_ = json.NewDecoder(r.Body).Decode(&body)
						value = body.Data["value"]
						_, _ = w.Write([]byte(`{}`))
						return
					}
					_, _ = w.Write([]byte(`{"data":{"data":{"value":"` + value + `"}}}`))
				case ProviderK8s:
					if r.Method == http.MethodPatch {
						var body struct {
							Data map[string]string `json:"data"`
						}
						_ = json.NewDecoder(r.Body).Decode(&body)
						decoded, _ := base64.StdEncoding.DecodeString(body.Data["value"])
						value = string(decoded)
						_, _ = w.Write([]byte(`{}`))
						return
					}
					_, _ = w.Write([]byte(`{"data":{"value":"` + base64.StdEncoding.EncodeToString([]byte(value)) + `"}}`))
				case ProviderAzure:
					if r.Method == http.MethodPut {
						var body map[string]string
						_ = json.NewDecoder(r.Body).Decode(&body)
						value = body["value"]
					}
					_, _ = w.Write([]byte(`{"value":"` + value + `"}`))
				case ProviderGCP:
					if r.Method == http.MethodPost {
						var body struct {
							Payload map[string]string `json:"payload"`
						}
						_ = json.NewDecoder(r.Body).Decode(&body)
						decoded, _ := base64.StdEncoding.DecodeString(body.Payload["data"])
						value = string(decoded)
						_, _ = w.Write([]byte(`{}`))
						return
					}
					_, _ = w.Write([]byte(`{"payload":{"data":"` + base64.StdEncoding.EncodeToString([]byte(value)) + `"}}`))
				case ProviderAWS:
					var body map[string]string
					_ = json.NewDecoder(r.Body).Decode(&body)
					if r.Header.Get("X-Amz-Target") == "secretsmanager.PutSecretValue" {
						value = body["SecretString"]
					}
					_, _ = w.Write([]byte(`{"SecretString":"` + value + `"}`))
				}
			}))
			defer server.Close()
			manager, err := NewConfiguredSecretsManager(SecretsManagerConfig{Provider: provider, Endpoint: server.URL, TokenEnv: "TEST_SECRET_TOKEN", Namespace: "security", Project: "project-a", Region: "us-east-1", Mount: "secret", HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			got, err := manager.GetSecret(t.Context(), "api-key")
			if err != nil || got != "initial" {
				t.Fatalf("initial read=%q error=%v", got, err)
			}
			if err := manager.SetSecret(t.Context(), "api-key", "updated"); err != nil {
				t.Fatal(err)
			}
			if err := manager.RotateSecret(t.Context(), "api-key", "rotated"); err != nil {
				t.Fatal(err)
			}
			got, err = manager.GetSecret(t.Context(), "api-key")
			if err != nil || got != "rotated" {
				t.Fatalf("rotated read=%q error=%v", got, err)
			}
		})
	}
}

func TestRemoteSecretBackendsRequireExplicitSecureConfiguration(t *testing.T) {
	for _, provider := range []ProviderType{ProviderVault, ProviderK8s, ProviderAWS, ProviderAzure, ProviderGCP} {
		if _, err := NewMultiBackendSecretsManager(provider).GetSecret(t.Context(), "api-key"); err == nil {
			t.Fatalf("%s silently configured itself", provider)
		}
	}
	if _, err := NewConfiguredSecretsManager(SecretsManagerConfig{Provider: ProviderVault, Endpoint: "http://vault.example", TokenEnv: "TOKEN"}); err == nil {
		t.Fatal("non-loopback plaintext secret endpoint must be rejected")
	}
}
