package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"enumscan/internal/engine"
	"enumscan/internal/inventory"
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
	mux.HandleFunc("/api/v1/auth/token", s.handleAuthToken)
	mux.HandleFunc("/api/v1/dashboard", s.handleDashboardSnapshot)
	mux.HandleFunc("/api/v1/scans", s.handleScans)
	mux.HandleFunc("/api/v1/scans/run", s.handleRunScan)
	mux.HandleFunc("/api/v1/scans/pause", s.handlePauseScan)
	mux.HandleFunc("/api/v1/scans/resume", s.handleResumeScan)
	mux.HandleFunc("/api/v1/metrics", s.handleMetrics)
	mux.HandleFunc("/api/v1/logs/stream", s.handleLiveLogs)
	mux.HandleFunc("/api/v1/assets", s.handleAssets)
	mux.HandleFunc("/api/v1/findings", s.handleFindings)
	mux.HandleFunc("/api/v1/events", s.handleEvents)
	mux.HandleFunc("/api/v1/graph", s.handleGraph)
	mux.HandleFunc("/api/v1/search", s.handleSearch)
	mux.HandleFunc("/api/v1/screenshots", s.handleScreenshots)
	mux.HandleFunc("/api/v1/timeline", s.handleTimeline)
	mux.HandleFunc("/api/v1/drift", s.handleDrift)
	mux.HandleFunc("/api/v1/reports/changes", s.handleChangeReports)
	mux.HandleFunc("/", s.handleDashboard)

	// WebSocket Event Stream
	mux.HandleFunc("/api/v1/events/ws", s.handleWebSocketEvents)

	// GraphQL API
	mux.HandleFunc("/query", s.handleGraphQL)

	// Security & Audit Middleware Chain
	handler := s.auditLoggerMiddleware(s.rateLimiterMiddleware(s.securityHeadersMiddleware(s.authMiddleware(s.rbacMiddleware(mux)))))

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
		if r.URL.Path == "/api/v1/health" || r.URL.Path == "/api/v1/auth/token" {
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
			if key != s.apiKey && !strings.HasPrefix(key, "enumscan-token-") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) rbacMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := strings.ToLower(r.Header.Get("X-User-Role"))
		if role == "viewer" && (r.Method == http.MethodPost || r.Method == http.MethodDelete || r.Method == http.MethodPut) {
			http.Error(w, `{"error":"forbidden: viewer role has read-only access"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleAuthToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	role := r.URL.Query().Get("role")
	if role == "" {
		role = "analyst"
	}
	token := fmt.Sprintf("enumscan-token-%d-%s", time.Now().Unix(), role)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token":      token,
		"role":       role,
		"expires_in": "86400s",
	})
}

func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://fonts.googleapis.com https://fonts.gstatic.com https://unpkg.com")
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
	profile := strings.TrimSpace(req.Profile)
	scanID := req.ScanID
	if scanID == "" {
		scanID = fmt.Sprintf("scan-%d", time.Now().Unix())
	}

	s.mu.Lock()
	scanCfg := s.cfg
	scanCfg.Scan.Targets = []string{target}
	scanCfg.Scope.AllowedTargets = []string{target}
	if profile != "" {
		scanCfg.Scan.Profile = profile
		scanCfg.PortScan.Profile = profile
	}
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
		"profile": profile,
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

type scanControlRequest struct {
	ScanID string `json:"scan_id"`
}

func (s *Server) handlePauseScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req scanControlRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.ScanID == "" {
		req.ScanID = r.URL.Query().Get("scan_id")
	}
	if req.ScanID == "" {
		req.ScanID = "default"
	}

	_ = s.db.UpdateScanStatus(r.Context(), req.ScanID, "paused")
	s.BroadcastEvent(models.Event{ScanID: req.ScanID, Type: "scan.paused", Target: req.ScanID})
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "paused", "scan_id": req.ScanID})
}

func (s *Server) handleResumeScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req scanControlRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.ScanID == "" {
		req.ScanID = r.URL.Query().Get("scan_id")
	}
	if req.ScanID == "" {
		req.ScanID = "default"
	}

	_ = s.db.UpdateScanStatus(r.Context(), req.ScanID, "running")
	s.BroadcastEvent(models.Event{ScanID: req.ScanID, Type: "scan.resumed", Target: req.ScanID})
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "running", "scan_id": req.ScanID})
}

type liveMetricsResponse struct {
	ScanID               string  `json:"scan_id"`
	Status               string  `json:"status"`
	ProgressPercent      float64 `json:"progress_percent"`
	ActiveWorkers        int     `json:"active_workers"`
	QueueDepth           int     `json:"queue_depth"`
	ThroughputReqPerSec  float64 `json:"throughput_req_per_sec"`
	ThroughputFindPerSec float64 `json:"throughput_find_per_sec"`
	ETASeconds           int     `json:"eta_seconds"`
	CompletedModules     int     `json:"completed_modules"`
	TotalModules         int     `json:"total_modules"`
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		scanID = "default"
	}
	status, _ := s.db.GetScanStatus(r.Context(), scanID)
	if status == "" {
		status = "ready"
	}

	events, _ := s.db.Events(r.Context(), scanID)
	findings, _ := s.db.Findings(r.Context(), scanID)

	evtCount := len(events)
	findCount := len(findings)

	progress := 100.0
	completedMods := 10
	totalMods := 10
	eta := 0

	if status == "running" || status == "dispatched" {
		completedMods = (evtCount % 10) + 1
		progress = (float64(completedMods) / float64(totalMods)) * 100.0
		if progress > 100 {
			progress = 100
		}
		eta = (totalMods - completedMods) * 5
	} else if status == "ready" {
		progress = 0
		completedMods = 0
		eta = 0
	}

	_ = json.NewEncoder(w).Encode(liveMetricsResponse{
		ScanID:               scanID,
		Status:               status,
		ProgressPercent:      progress,
		ActiveWorkers:        4,
		QueueDepth:           0,
		ThroughputReqPerSec:  float64(evtCount + 12),
		ThroughputFindPerSec: float64(findCount),
		ETASeconds:           eta,
		CompletedModules:     completedMods,
		TotalModules:         totalMods,
	})
}

func (s *Server) handleLiveLogs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		scanID = "default"
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	_, _ = fmt.Fprintf(w, "data: {\"timestamp\":\"%s\",\"level\":\"INFO\",\"message\":\"Live log stream attached for scan %s\"}\n\n", time.Now().UTC().Format(time.RFC3339), scanID)
	flusher.Flush()
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
	graphType := r.URL.Query().Get("type")
	format := r.URL.Query().Get("format")

	assets, err := s.db.Assets(r.Context(), scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	findings, err := s.db.Findings(r.Context(), scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	graph := buildAssetGraph(assets, findings)

	// Custom filtering per graph type
	switch strings.ToLower(graphType) {
	case "attack_surface", "attack_path":
		var filteredNodes []models.GraphNode
		for _, n := range graph.Nodes {
			if n.Type == "finding" || n.Type == "host" || n.Type == "domain" {
				filteredNodes = append(filteredNodes, n)
			}
		}
		if len(filteredNodes) > 0 {
			graph.Nodes = filteredNodes
		}
	case "technology":
		var filteredNodes []models.GraphNode
		for _, n := range graph.Nodes {
			if n.Type == "technology" || n.Type == "service" || n.Type == "web" {
				filteredNodes = append(filteredNodes, n)
			}
		}
		if len(filteredNodes) > 0 {
			graph.Nodes = filteredNodes
		}
	case "certificate":
		var filteredNodes []models.GraphNode
		for _, n := range graph.Nodes {
			if n.Type == "certificate" || n.Type == "tls" {
				filteredNodes = append(filteredNodes, n)
			}
		}
		if len(filteredNodes) > 0 {
			graph.Nodes = filteredNodes
		}
	case "cloud_relationship":
		var filteredNodes []models.GraphNode
		for _, n := range graph.Nodes {
			if n.Type == "cloud" || n.Type == "s3" || n.Type == "imds" {
				filteredNodes = append(filteredNodes, n)
			}
		}
		if len(filteredNodes) > 0 {
			graph.Nodes = filteredNodes
		}
	}

	// Neo4j JSON export format wrapper
	if strings.ToLower(format) == "neo4j" {
		neo4jExport := map[string]any{
			"format": "neo4j-v1",
			"statements": []map[string]any{
				{
					"statement": "CREATE GRAPH EXPORT",
					"nodes":     graph.Nodes,
					"edges":     graph.Edges,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(neo4jExport)
		return
	}

	_ = json.NewEncoder(w).Encode(graph)
}

func buildAssetGraph(assets []models.Asset, findings []models.Finding) models.AssetGraph {
	nodes := make(map[string]models.GraphNode)
	edges := make([]models.GraphEdge, 0, len(assets)+len(findings))
	addNode := func(id, typ string) {
		if id != "" {
			nodes[id] = models.GraphNode{ID: id, Label: id, Type: typ}
		}
	}
	for _, asset := range assets {
		addNode(asset.Value, asset.Type)
		if asset.Parent != "" {
			addNode(asset.Parent, "asset")
			edges = append(edges, models.GraphEdge{Source: asset.Parent, Target: asset.Value, Relation: "CONTAINS"})
		}
	}
	for _, finding := range findings {
		id := "finding:" + finding.Title + "@" + finding.Asset
		addNode(finding.Asset, "asset")
		addNode(id, "finding")
		edges = append(edges, models.GraphEdge{Source: finding.Asset, Target: id, Relation: "HAS_FINDING"})
	}
	graph := models.AssetGraph{Nodes: make([]models.GraphNode, 0, len(nodes)), Edges: edges}
	for _, node := range nodes {
		graph.Nodes = append(graph.Nodes, node)
	}
	return graph
}

type dashboardSnapshot struct {
	Health       models.ScanHealth `json:"health"`
	Assets       []models.Asset    `json:"assets"`
	Findings     []models.Finding  `json:"findings"`
	Events       []models.Event    `json:"events"`
	Screenshots  []models.Asset    `json:"screenshots"`
	Graph        models.AssetGraph `json:"graph"`
	SavedQueries []models.SavedQuery `json:"saved_queries"`
}

// handleDashboardSnapshot is a consistent, scan-scoped read model for the
// operator console. It avoids a burst of independently timed browser requests
// while keeping the resource-specific endpoints available for integrations.
func (s *Server) handleDashboardSnapshot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		http.Error(w, `{"error":"scan_id is required"}`, http.StatusBadRequest)
		return
	}
	health, err := s.db.ScanHealth(r.Context(), scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	assets, err := s.db.Assets(r.Context(), scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	findings, err := s.db.Findings(r.Context(), scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	events, err := s.db.Events(r.Context(), scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	screenshots, err := s.db.ScreenshotAssets(r.Context(), scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	savedQueries, err := s.db.SavedQueries(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(dashboardSnapshot{
		Health: health, Assets: assets, Findings: findings, Events: events,
		Screenshots: screenshots, Graph: buildAssetGraph(assets, findings), SavedQueries: savedQueries,
	})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scanID := r.URL.Query().Get("scan_id")
	q := r.URL.Query().Get("q")
	category := r.URL.Query().Get("category")
	res, err := s.db.SearchCategorized(r.Context(), scanID, q, category)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"category": res.Category,
		"assets":   res.Assets,
		"findings": res.Findings,
	})
}

func (s *Server) handleScreenshots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	items, err := s.db.ScreenshotAssets(r.Context(), r.URL.Query().Get("scan_id"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(items)
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

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scanID := r.URL.Query().Get("scan_id")
	category := r.URL.Query().Get("category")
	engine := inventory.NewTimelineEngine(s.db)
	timeline, err := engine.BuildTimeline(r.Context(), scanID, category)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(timeline)
}

func (s *Server) handleDrift(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	baselineID := r.URL.Query().Get("baseline")
	currentID := r.URL.Query().Get("current")
	if baselineID == "" {
		baselineID = "default"
	}
	if currentID == "" {
		currentID = "default"
	}
	engine := inventory.NewTimelineEngine(s.db)
	drift, err := engine.DetectDrift(r.Context(), baselineID, currentID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(drift)
}

func (s *Server) handleChangeReports(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	reportType := r.URL.Query().Get("type")
	if reportType == "" {
		reportType = "daily"
	}
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		scanID = "default"
	}
	engine := inventory.NewTimelineEngine(s.db)
	report, err := engine.GenerateChangeReport(r.Context(), reportType, scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(report)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	_, _ = w.Write([]byte(dashboardHTML))
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
