package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"enumscan/internal/engine"
	"enumscan/internal/models"
	"enumscan/internal/store"
)

type Server struct {
	db        *store.SQLiteCLI
	cfg       models.Config
	port      int
	apiKey    string
	certFile  string
	keyFile   string
	mu        sync.RWMutex
	wsClients map[chan models.Event]bool
	httpSrv   *http.Server
	rateMap   map[string]time.Time
}

func NewServer(db *store.SQLiteCLI, port int) *Server {
	if port <= 0 {
		port = 8080
	}
	return &Server{
		db:        db,
		port:      port,
		wsClients: make(map[chan models.Event]bool),
		rateMap:   make(map[string]time.Time),
	}
}

func (s *Server) SetConfig(cfg models.Config) {
	s.cfg = cfg
}

func (s *Server) SetAPIKey(key string) {
	s.apiKey = key
}

func (s *Server) SetTLS(certFile, keyFile string) {
	s.certFile = certFile
	s.keyFile = keyFile
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	mux := http.NewServeMux()

	// REST Endpoints
	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/scans", s.handleScans)
	mux.HandleFunc("/api/v1/scans/run", s.handleRunScan)
	mux.HandleFunc("/api/v1/assets", s.handleAssets)
	mux.HandleFunc("/api/v1/findings", s.handleFindings)
	mux.HandleFunc("/api/v1/events", s.handleEvents)
	mux.HandleFunc("/api/v1/graph", s.handleGraph)
	mux.HandleFunc("/api/v1/search", s.handleSearch)
	mux.HandleFunc("/api/v1/screenshots", s.handleScreenshots)
	mux.HandleFunc("/api/v1/saved-queries", s.handleSavedQueries)
	mux.HandleFunc("/", s.handleDashboard)

	// WebSocket Event Stream
	mux.HandleFunc("/api/v1/events/ws", s.handleWebSocketEvents)

	// GraphQL API
	mux.HandleFunc("/query", s.handleGraphQL)

	// Security & Audit Middleware Chain
	handler := s.auditLoggerMiddleware(s.rateLimiterMiddleware(s.securityHeadersMiddleware(s.authMiddleware(mux))))

	s.httpSrv = &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", s.port),
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		_ = s.httpSrv.Shutdown(context.Background())
	}()

	if s.certFile != "" && s.keyFile != "" {
		return s.httpSrv.ListenAndServeTLS(s.certFile, s.keyFile)
	}

	return s.httpSrv.ListenAndServe()
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health check is unauthenticated
		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}

		if s.apiKey != "" {
			key := r.Header.Get("X-API-Key")
			if key == "" {
				authHeader := r.Header.Get("Authorization")
				if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
					key = authHeader[7:]
				}
			}
			if key != s.apiKey {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com https://fonts.gstatic.com")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) rateLimiterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		s.mu.Lock()
		last, exists := s.rateMap[ip]
		now := time.Now()
		if exists && now.Sub(last) < 1*time.Millisecond {
			s.mu.Unlock()
			http.Error(w, `{"error":"too many requests"}`, http.StatusTooManyRequests)
			return
		}
		s.rateMap[ip] = now
		s.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}

func (s *Server) auditLoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[AUDIT] %s %s %s duration=%s", r.RemoteAddr, r.Method, r.URL.Path, time.Since(start))
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := s.db.Ping(r.Context()); err != nil {
		http.Error(w, `{"status":"unhealthy","error":"database unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	response := map[string]any{"status": "ok", "timestamp": time.Now().UTC().Format(time.RFC3339)}
	if scanID := r.URL.Query().Get("scan_id"); scanID != "" {
		health, err := s.db.ScanHealth(r.Context(), scanID)
		if err != nil {
			http.Error(w, `{"status":"unhealthy","error":"scan health unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		response["scan"] = health
		if !health.Healthy {
			response["status"] = "degraded"
		}
	}
	_ = json.NewEncoder(w).Encode(response)
}

type runScanRequest struct {
	ScanID  string `json:"scan_id"`
	Target  string `json:"target"`
	Profile string `json:"profile"`
}

func (s *Server) handleRunScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req runScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Target) == "" {
		http.Error(w, `{"error":"target is required"}`, http.StatusBadRequest)
		return
	}

	target := strings.TrimSpace(req.Target)
	scanID := req.ScanID
	if scanID == "" {
		scanID = fmt.Sprintf("scan-%d", time.Now().Unix())
	}

	s.mu.Lock()
	scanCfg := s.cfg
	scanCfg.Scan.Targets = []string{target}
	scanCfg.Scope.AllowedTargets = []string{target}
	s.cfg = scanCfg
	s.mu.Unlock()

	ctx := context.Background()
	if err := s.db.Migrate(ctx); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"db migrate: %v"}`, err), http.StatusInternalServerError)
		return
	}

	s.BroadcastEvent(models.Event{ScanID: scanID, Type: "scan.dispatched", Target: target})

	go func(sID string, tgt string, cfg models.Config) {
		runner := engine.New(cfg, s.db)
		scanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		s.BroadcastEvent(models.Event{ScanID: sID, Type: "engine.started", Target: tgt})
		if err := runner.Run(scanCtx, sID); err != nil {
			log.Printf("[ENGINE] Scan error (%s): %v", sID, err)
			s.BroadcastEvent(models.Event{ScanID: sID, Type: "scan.failed", Target: fmt.Sprintf("%s: %v", tgt, err)})
		} else {
			log.Printf("[ENGINE] Scan completed (%s) for target %s", sID, tgt)
			s.BroadcastEvent(models.Event{ScanID: sID, Type: "scan.completed", Target: tgt})
		}
	}(scanID, target, scanCfg)

	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "dispatched",
		"scan_id": scanID,
		"target":  target,
	})
}

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		scanID = "default"
	}
	status, err := s.db.GetScanStatus(r.Context(), scanID)
	if err != nil || status == "" {
		status = "unknown"
	}
	_ = json.NewEncoder(w).Encode(map[string]string{
		"scan_id": scanID,
		"status":  status,
	})
}

type deleteRequest struct {
	IDs []int64 `json:"ids"`
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodDelete {
		var req deleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.IDs) == 0 {
			if idStr := r.URL.Query().Get("id"); idStr != "" {
				var id int64
				if _, err := fmt.Sscanf(idStr, "%d", &id); err == nil {
					req.IDs = []int64{id}
				}
			}
		}
		if len(req.IDs) == 0 {
			http.Error(w, `{"error":"no ids provided"}`, http.StatusBadRequest)
			return
		}
		if err := s.db.DeleteAssets(r.Context(), req.IDs); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"delete assets failed: %v"}`, err), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "deleted", "deleted_count": len(req.IDs)})
		return
	}

	scanID := r.URL.Query().Get("scan_id")
	assets, err := s.db.Assets(r.Context(), scanID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	var filtered []models.Asset
	for _, a := range assets {
		val := strings.ToLower(a.Value)
		parent := strings.ToLower(a.Parent)
		if strings.Contains(val, "127.0.0.1") || strings.Contains(val, "localhost") ||
			strings.Contains(parent, "127.0.0.1") || strings.Contains(parent, "localhost") {
			continue
		}
		filtered = append(filtered, a)
	}
	if filtered == nil {
		filtered = []models.Asset{}
	}
	_ = json.NewEncoder(w).Encode(filtered)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodDelete {
		var req deleteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.IDs) == 0 {
			if idStr := r.URL.Query().Get("id"); idStr != "" {
				var id int64
				if _, err := fmt.Sscanf(idStr, "%d", &id); err == nil {
					req.IDs = []int64{id}
				}
			}
		}
		if len(req.IDs) == 0 {
			http.Error(w, `{"error":"no ids provided"}`, http.StatusBadRequest)
			return
		}
		if err := s.db.DeleteFindings(r.Context(), req.IDs); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"delete findings failed: %v"}`, err), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "deleted", "deleted_count": len(req.IDs)})
		return
	}

	scanID := r.URL.Query().Get("scan_id")
	findings, err := s.db.Findings(r.Context(), scanID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	var filtered []models.Finding
	for _, f := range findings {
		asset := strings.ToLower(f.Asset)
		if strings.Contains(asset, "127.0.0.1") || strings.Contains(asset, "localhost") {
			continue
		}
		filtered = append(filtered, f)
	}
	if filtered == nil {
		filtered = []models.Finding{}
	}
	_ = json.NewEncoder(w).Encode(filtered)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scanID := r.URL.Query().Get("scan_id")
	events, err := s.db.Events(r.Context(), scanID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if events == nil {
		events = []models.Event{}
	}
	_ = json.NewEncoder(w).Encode(events)
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scanID := r.URL.Query().Get("scan_id")
	assets, _ := s.db.Assets(r.Context(), scanID)
	findings, _ := s.db.Findings(r.Context(), scanID)
	if assets == nil {
		assets = []models.Asset{}
	}
	if findings == nil {
		findings = []models.Finding{}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"nodes": assets,
		"edges": findings,
	})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	query := r.URL.Query().Get("q")
	scanID := r.URL.Query().Get("scan_id")
	assets, _ := s.db.Assets(r.Context(), scanID)
	var matched []models.Asset
	for _, a := range assets {
		if query == "" || strings.Contains(a.Value, query) || strings.Contains(a.Type, query) {
			matched = append(matched, a)
		}
	}
	_ = json.NewEncoder(w).Encode(matched)
}

func (s *Server) handleScreenshots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode([]string{})
}

func (s *Server) handleSavedQueries(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodPost {
		var sq models.SavedQuery
		if err := json.NewDecoder(r.Body).Decode(&sq); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.db.SaveQuery(r.Context(), sq.Name, sq.Query); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "created"})
		return
	}
	queries, err := s.db.SavedQueries(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(queries)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	content, err := os.ReadFile("dashboardtemplate.html")
	if err != nil {
		content, err = os.ReadFile("../dashboardtemplate.html")
	}
	if err != nil {
		_, _ = w.Write([]byte("<!DOCTYPE html><html><body><h1>EnumScan Operator Dashboard</h1><p>dashboardtemplate.html not found</p></body></html>"))
		return
	}
	_, _ = w.Write(content)
}

func (s *Server) BroadcastEvent(evt models.Event) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for ch := range s.wsClients {
		select {
		case ch <- evt:
		default:
		}
	}
}

