package api

import (
	"encoding/json"
	"net/http"
)

// OpenAPIv1Spec returns the authoritative OpenAPI 3.0 specification for Enumscan.
func OpenAPIv1Spec() map[string]any {
	return map[string]any{
		"openapi": "3.0.3",
		"info": map[string]any{
			"title":       "Enumscan API",
			"version":     "v1",
			"description": "Authorized reconnaissance, attack surface enumeration, and security assessment pipeline API.",
			"contact": map[string]any{
				"name": "Enumscan Security Engineering",
			},
		},
		"servers": []map[string]any{
			{
				"url":         "http://127.0.0.1:8080",
				"description": "Local Operator Console API",
			},
		},
		"paths": map[string]any{
			"/api/v1/health": map[string]any{
				"get": map[string]any{
					"summary":     "System health and datastore connectivity status",
					"operationId": "getHealth",
					"responses": map[string]any{
						"200": map[string]any{"description": "System is healthy"},
						"503": map[string]any{"description": "Datastore or pipeline failure"},
					},
				},
			},
			"/api/v1/capabilities": map[string]any{
				"get": map[string]any{
					"summary":     "Product capability manifest and feature statuses",
					"operationId": "getCapabilities",
					"responses": map[string]any{
						"200": map[string]any{"description": "Authoritative capability list"},
					},
				},
			},
			"/api/v1/engagement/plan": map[string]any{
				"post": map[string]any{
					"summary":     "Generate and preview a scope-locked safe engagement configuration",
					"operationId": "generateEngagementPlan",
					"requestBody": map[string]any{
						"required": true,
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": map[string]any{
									"type": "object",
									"required": []string{"target", "authorization"},
									"properties": map[string]any{
										"target":        map[string]any{"type": "string"},
										"profile":       map[string]any{"type": "string"},
										"authorization": map[string]any{"type": "string"},
										"filename":      map[string]any{"type": "string"},
									},
								},
							},
						},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Scope-locked configuration preview and estimates"},
						"400": map[string]any{"description": "Invalid target or missing authorization"},
					},
				},
			},
			"/api/v1/scans": map[string]any{
				"get": map[string]any{
					"summary":     "List recent persisted scan executions",
					"operationId": "listScans",
					"parameters": []map[string]any{
						{"name": "limit", "in": "query", "schema": map[string]any{"type": "integer"}},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Array of scan run summaries"},
					},
				},
			},
			"/api/v1/scans/run": map[string]any{
				"post": map[string]any{
					"summary":     "Trigger an authorized enumeration scan run",
					"operationId": "runScan",
					"responses": map[string]any{
						"200": map[string]any{"description": "Scan started"},
						"403": map[string]any{"description": "Forbidden or out-of-scope"},
					},
				},
			},
			"/api/v1/assets": map[string]any{
				"get": map[string]any{
					"summary":     "List discovered assets for a scan",
					"operationId": "listAssets",
					"parameters": []map[string]any{
						{"name": "scan_id", "in": "query", "required": true, "schema": map[string]any{"type": "string"}},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Array of discovered assets"},
					},
				},
			},
			"/api/v1/findings": map[string]any{
				"get": map[string]any{
					"summary":     "List security findings and exposures",
					"operationId": "listFindings",
					"parameters": []map[string]any{
						{"name": "scan_id", "in": "query", "required": true, "schema": map[string]any{"type": "string"}},
					},
					"responses": map[string]any{
						"200": map[string]any{"description": "Array of security findings"},
					},
				},
			},
			"/api/v1/metrics": map[string]any{
				"get": map[string]any{
					"summary":     "Prometheus-compatible system and scan metrics",
					"operationId": "getMetrics",
					"responses": map[string]any{
						"200": map[string]any{"description": "OpenMetrics text exposition format"},
					},
				},
			},
			"/api/v1/identity/organizations": map[string]any{
				"get": map[string]any{
					"summary":     "List enterprise tenant organizations",
					"operationId": "listOrganizations",
					"responses": map[string]any{
						"200": map[string]any{"description": "Array of tenant organizations"},
					},
				},
				"post": map[string]any{
					"summary":     "Register a new enterprise tenant organization",
					"operationId": "createOrganization",
					"responses": map[string]any{
						"201": map[string]any{"description": "Organization created"},
					},
				},
			},
			"/api/v1/openapi.json": map[string]any{
				"get": map[string]any{
					"summary":     "Authoritative OpenAPI 3.0 specification",
					"operationId": "getOpenAPISpec",
					"responses": map[string]any{
						"200": map[string]any{"description": "OpenAPI specification JSON"},
					},
				},
			},
		},
		"components": map[string]any{
			"schemas": map[string]any{
				"ScanRun": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"scan_id":       map[string]any{"type": "string"},
						"status":        map[string]any{"type": "string"},
						"started_at":    map[string]any{"type": "string", "format": "date-time"},
						"finished_at":   map[string]any{"type": "string", "format": "date-time"},
						"asset_count":   map[string]any{"type": "integer"},
						"finding_count": map[string]any{"type": "integer"},
						"event_count":   map[string]any{"type": "integer"},
					},
				},
				"Asset": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id":         map[string]any{"type": "integer"},
						"scan_id":    map[string]any{"type": "string"},
						"type":       map[string]any{"type": "string"},
						"value":      map[string]any{"type": "string"},
						"parent":     map[string]any{"type": "string"},
						"created_at": map[string]any{"type": "string", "format": "date-time"},
					},
				},
				"Finding": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id":          map[string]any{"type": "integer"},
						"scan_id":     map[string]any{"type": "string"},
						"severity":    map[string]any{"type": "string"},
						"confidence":  map[string]any{"type": "string"},
						"asset":       map[string]any{"type": "string"},
						"title":       map[string]any{"type": "string"},
						"evidence":    map[string]any{"type": "string"},
						"remediation": map[string]any{"type": "string"},
					},
				},
				"Organization": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"id":             map[string]any{"type": "string"},
						"name":           map[string]any{"type": "string"},
						"domain":         map[string]any{"type": "string"},
						"allowed_scopes": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					},
				},
			},
		},
	}
}

func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(OpenAPIv1Spec())
}
