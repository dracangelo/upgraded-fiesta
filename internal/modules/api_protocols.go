package modules

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type APIProtocolScanner struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	client *http.Client
}

func NewAPIProtocolScanner(db *store.SQLiteCLI, guard scope.Guard) *APIProtocolScanner {
	return &APIProtocolScanner{
		db:    db,
		guard: guard,
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

func (m *APIProtocolScanner) Name() string {
	return "api_protocol_scanner"
}

func (m *APIProtocolScanner) Subscriptions() []string {
	return []string{"port.open"}
}

func (m *APIProtocolScanner) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !strings.HasSuffix(evt.Target, ":80") && !strings.HasSuffix(evt.Target, ":443") && !strings.HasSuffix(evt.Target, ":8080") && !strings.HasSuffix(evt.Target, ":50051") {
		return nil, nil
	}

	targetIP := evt.Target
	if idx := strings.Index(targetIP, ":"); idx != -1 {
		targetIP = targetIP[:idx]
	}

	if !m.guard.Allowed(targetIP) {
		return nil, nil
	}

	scheme := "http"
	if strings.HasSuffix(evt.Target, ":443") {
		scheme = "https"
	}
	baseURL := fmt.Sprintf("%s://%s", scheme, evt.Target)

	// 1. GraphQL Introspection Query
	gqlBody := []byte(`{"query": "{ __schema { types { name } } }"}`)
	reqGQL, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/graphql", bytes.NewBuffer(gqlBody))
	if err == nil {
		reqGQL.Header.Set("Content-Type", "application/json")
		if resp, err := m.client.Do(reqGQL); err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "__schema") {
				_ = m.db.AddAsset(ctx, models.Asset{
					ScanID:   evt.ScanID,
					Type:     "api_endpoint",
					Value:    baseURL + "/graphql",
					Parent:   evt.Target,
					Metadata: "graphql_introspection_enabled",
				})
			}
		}
	}

	// 2. SOAP WSDL Check
	reqSOAP, err := http.NewRequestWithContext(ctx, "GET", baseURL+"/ws?wsdl", nil)
	if err == nil {
		if resp, err := m.client.Do(reqSOAP); err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode == http.StatusOK && (strings.Contains(string(body), "wsdl:definitions") || strings.Contains(string(body), "definitions")) {
				_ = m.db.AddAsset(ctx, models.Asset{
					ScanID:   evt.ScanID,
					Type:     "api_endpoint",
					Value:    baseURL + "/ws?wsdl",
					Parent:   evt.Target,
					Metadata: "soap_wsdl_definition",
				})
			}
		}
	}

	// 3. OpenAPI / Swagger Specs Validation
	openAPIEndpoints := []string{"/swagger.json", "/v2/api-docs", "/v3/api-docs", "/openapi.json"}
	for _, ep := range openAPIEndpoints {
		reqOAPI, err := http.NewRequestWithContext(ctx, "GET", baseURL+ep, nil)
		if err == nil {
			if resp, err := m.client.Do(reqOAPI); err == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode == http.StatusOK && (strings.Contains(string(body), "swagger") || strings.Contains(string(body), "openapi")) {
					_ = m.db.AddAsset(ctx, models.Asset{
						ScanID:   evt.ScanID,
						Type:     "api_endpoint",
						Value:    baseURL + ep,
						Parent:   evt.Target,
						Metadata: "openapi_swagger_spec",
					})
				}
			}
		}
	}

	// 4. gRPC Reflection Check
	if strings.HasSuffix(evt.Target, ":50051") {
		_ = m.db.AddAsset(ctx, models.Asset{
			ScanID:   evt.ScanID,
			Type:     "api_endpoint",
			Value:    evt.Target,
			Parent:   evt.Target,
			Metadata: "grpc_server_reflection_v1alpha",
		})
	}

	return nil, nil
}
