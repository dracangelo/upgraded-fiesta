package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

func (s *Server) handleEngagements(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	sqliteStore, ok := s.db.(*store.SQLiteCLI)
	if !ok || sqliteStore == nil {
		http.Error(w, `{"error":"engagement operations require configured operational datastore"}`, http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodPost:
		var eng models.Engagement
		if err := json.NewDecoder(r.Body).Decode(&eng); err != nil {
			http.Error(w, `{"error":"invalid engagement request body"}`, http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(eng.ID) == "" {
			eng.ID = fmt.Sprintf("eng_%d", time.Now().UnixNano())
		}
		if err := sqliteStore.CreateEngagement(r.Context(), eng); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(eng)

	case http.MethodGet:
		id := r.URL.Query().Get("id")
		if id != "" {
			eng, err := sqliteStore.GetEngagement(r.Context(), id)
			if err != nil {
				http.Error(w, `{"error":"engagement not found"}`, http.StatusNotFound)
				return
			}
			scans, _ := sqliteStore.ListEngagementScans(r.Context(), id)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"engagement": eng,
				"scans":      scans,
			})
			return
		}

		orgID := r.URL.Query().Get("org_id")
		list, err := sqliteStore.ListEngagements(r.Context(), orgID)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(list)

	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}
