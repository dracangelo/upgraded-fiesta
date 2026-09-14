package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func (s *Server) handleFindingReview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sqliteStore, ok := s.db.(*store.SQLiteCLI)
	if !ok || sqliteStore == nil {
		http.Error(w, `{"error":"finding review operations require operational datastore"}`, http.StatusServiceUnavailable)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		FindingID     int64               `json:"finding_id"`
		State         models.FindingState `json:"state"`
		Actor         string              `json:"actor"`
		Justification string              `json:"justification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid review request body"}`, http.StatusBadRequest)
		return
	}

	if err := sqliteStore.UpdateFindingReviewState(r.Context(), req.FindingID, req.State, req.Actor, req.Justification); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "updated",
		"finding_id": req.FindingID,
		"new_state":  req.State,
	})
}

func (s *Server) handleFindingAssign(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sqliteStore, ok := s.db.(*store.SQLiteCLI)
	if !ok || sqliteStore == nil {
		http.Error(w, `{"error":"finding review operations require operational datastore"}`, http.StatusServiceUnavailable)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		FindingID int64  `json:"finding_id"`
		Assignee  string `json:"assignee"`
		Actor     string `json:"actor"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid assign request body"}`, http.StatusBadRequest)
		return
	}

	if err := sqliteStore.AssignFinding(r.Context(), req.FindingID, req.Assignee, req.Actor); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "assigned",
		"finding_id": req.FindingID,
		"assignee":   req.Assignee,
	})
}

func (s *Server) handleFindingAudit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sqliteStore, ok := s.db.(*store.SQLiteCLI)
	if !ok || sqliteStore == nil {
		http.Error(w, `{"error":"finding review operations require operational datastore"}`, http.StatusServiceUnavailable)
		return
	}

	findingIDStr := r.URL.Query().Get("finding_id")
	findingID, err := strconv.ParseInt(findingIDStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"valid finding_id parameter required"}`, http.StatusBadRequest)
		return
	}

	history, err := sqliteStore.FindingAuditHistory(r.Context(), findingID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}

	_ = json.NewEncoder(w).Encode(history)
}
