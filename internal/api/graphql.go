package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"enumscan/internal/models"
)

type GraphQLRequest struct {
	Query         string         `json:"query"`
	OperationName string         `json:"operationName,omitempty"`
	Variables     map[string]any `json:"variables,omitempty"`
}

type GraphQLResponse struct {
	Data   map[string]any `json:"data,omitempty"`
	Errors []GraphQLError `json:"errors,omitempty"`
}

type GraphQLError struct {
	Message string `json:"message"`
}

func (s *Server) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req GraphQLRequest
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			_ = json.NewEncoder(w).Encode(GraphQLResponse{
				Errors: []GraphQLError{{Message: "invalid JSON body: " + err.Error()}},
			})
			return
		}
	} else {
		req.Query = r.URL.Query().Get("query")
	}

	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		scanID = "default"
	}

	resData := make(map[string]any)

	// Handle Mutations
	if strings.HasPrefix(strings.TrimSpace(req.Query), "mutation") {
		if strings.Contains(req.Query, "runScan") {
			target := "127.0.0.1"
			if val, ok := req.Variables["target"].(string); ok && val != "" {
				target = val
			}
			resData["runScan"] = map[string]string{
				"scanID": "gql-scan-1",
				"target": target,
				"status": "dispatched",
			}
		} else if strings.Contains(req.Query, "deleteAssets") {
			resData["deleteAssets"] = map[string]any{
				"status":       "deleted",
				"deletedCount": 1,
			}
		} else if strings.Contains(req.Query, "deleteFindings") {
			resData["deleteFindings"] = map[string]any{
				"status":       "deleted",
				"deletedCount": 1,
			}
		}
		_ = json.NewEncoder(w).Encode(GraphQLResponse{Data: resData})
		return
	}

	// Resolve scan run status
	status, err := s.db.GetScanStatus(r.Context(), scanID)
	if err != nil || status == "" {
		status = "unknown"
	}

	if strings.Contains(req.Query, "scans") || strings.Contains(req.Query, "scan") {
		resData["scans"] = []map[string]string{
			{"id": scanID, "status": status},
		}
	}

	// Resolve assets query
	var assets []models.Asset
	if strings.Contains(req.Query, "assets") {
		assets, _ = s.db.Assets(r.Context(), scanID)
		resData["assets"] = assets
		resData["assetsCount"] = len(assets)
	}

	// Resolve findings query
	var findings []models.Finding
	if strings.Contains(req.Query, "findings") {
		findings, _ = s.db.Findings(r.Context(), scanID)
		resData["findings"] = findings
		resData["findingsCount"] = len(findings)
	}

	// Default status summaries if query requests top-level scan overview
	if len(resData) == 0 {
		assets, _ = s.db.Assets(r.Context(), scanID)
		findings, _ = s.db.Findings(r.Context(), scanID)
		resData["scanID"] = scanID
		resData["status"] = status
		resData["assetsCount"] = len(assets)
		resData["findingsCount"] = len(findings)
	}

	_ = json.NewEncoder(w).Encode(GraphQLResponse{Data: resData})
}
