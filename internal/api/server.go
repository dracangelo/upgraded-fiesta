package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

type Server struct {
	db       *store.SQLiteCLI
	port     int
	mu       sync.RWMutex
	clients  map[chan models.Event]bool
	httpSrv *http.Server
}

func NewServer(db *store.SQLiteCLI, port int) *Server {
	if port <= 0 {
		port = 8080
	}
	return &Server{
		db:      db,
		port:    port,
		clients: make(map[chan models.Event]bool),
	}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()

	// REST Endpoints
	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/scans", s.handleScans)
	mux.HandleFunc("/api/v1/assets", s.handleAssets)
	mux.HandleFunc("/api/v1/findings", s.handleFindings)

	// WebSocket Event Stream
	mux.HandleFunc("/api/v1/events/ws", s.handleWebSocketEvents)

	// GraphQL API
	mux.HandleFunc("/query", s.handleGraphQL)

	s.httpSrv = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		_ = s.httpSrv.Shutdown(context.Background())
	}()

	return s.httpSrv.ListenAndServe()
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok", "timestamp": time.Now().Format(time.RFC3339)})
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		scanID = "default"
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID, "status": "active"})
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scanID := r.URL.Query().Get("scan_id")
	assets, err := s.db.Assets(r.Context(), scanID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_ = json.NewEncoder(w).Encode(assets)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scanID := r.URL.Query().Get("scan_id")
	findings, err := s.db.Findings(r.Context(), scanID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_ = json.NewEncoder(w).Encode(findings)
}

func (s *Server) handleWebSocketEvents(w http.ResponseWriter, r *http.Request) {
	// Simple HTTP event stream fallback / WebSocket header response
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := make(chan models.Event, 10)
	s.mu.Lock()
	s.clients[ch] = true
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.clients, ch)
		s.mu.Unlock()
		close(ch)
	}()

	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}

	fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	for {
		select {
		case evt := <-ch:
			data, _ := json.Marshal(evt)
			fmt.Fprintf(w, "data: %s\n\n", string(data))
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) BroadcastEvent(evt models.Event) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for ch := range s.clients {
		select {
		case ch <- evt:
		default:
		}
	}
}

func (s *Server) handleGraphQL(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	type gqlRequest struct {
		Query string `json:"query"`
	}
	var req gqlRequest
	if r.Method == "POST" {
		_ = json.NewDecoder(r.Body).Decode(&req)
	} else {
		req.Query = r.URL.Query().Get("query")
	}

	scanID := r.URL.Query().Get("scan_id")
	assets, _ := s.db.Assets(r.Context(), scanID)
	findings, _ := s.db.Findings(r.Context(), scanID)

	response := map[string]any{
		"data": map[string]any{
			"scans": []map[string]string{{"id": scanID, "status": "completed"}},
			"assetsCount": len(assets),
			"findingsCount": len(findings),
		},
	}

	if strings.Contains(req.Query, "findings") {
		response["data"].(map[string]any)["findings"] = findings
	}
	if strings.Contains(req.Query, "assets") {
		response["data"].(map[string]any)["assets"] = assets
	}

	_ = json.NewEncoder(w).Encode(response)
}
