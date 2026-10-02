package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"enumscan/internal/capability"
	"enumscan/internal/config"
	"enumscan/internal/engine"
	"enumscan/internal/inventory"
	"enumscan/internal/models"
	"enumscan/internal/modules"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type Server struct {
	db             store.RuntimeStore
	cfg            models.Config
	port           int
	listenAddress  string
	apiKey         string
	apiTokens      map[string]string
	apiTokenLoader func() (map[string]string, error)
	certFile       string
	keyFile        string
	mu             sync.RWMutex
	wsClients      map[chan models.Event]bool
	httpSrv        *http.Server
	rateMap        map[string]time.Time
	identityMgr    *IdentityManager
}

type apiPrincipal struct {
	role  string
	actor string
}
type apiPrincipalContextKey struct{}

func NewServer(db store.RuntimeStore, port int) *Server {
	if port <= 0 {
		port = 8080
	}
	return &Server{
		db:            db,
		port:          port,
		listenAddress: "127.0.0.1",
		wsClients:     make(map[chan models.Event]bool),
		rateMap:       make(map[string]time.Time),
		apiTokens:     make(map[string]string),
		identityMgr:   NewIdentityManager(),
	}
}

// SetListenAddress enables an explicitly configured coordinator bind address.
// Non-loopback listeners are accepted only when TLS is configured.
func (s *Server) SetListenAddress(address string) {
	s.listenAddress = strings.TrimSpace(address)
}

func (s *Server) SetConfig(cfg models.Config) {
	s.cfg = cfg
}

func (s *Server) SetAPIKey(key string) {
	s.apiKey = key
}

// SetAPITokens configures server-assigned roles for opaque API tokens. Tokens
// are passed from an environment variable by the CLI, never persisted in YAML.
func (s *Server) SetAPITokens(tokens map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiTokens = normalizeAPITokens(tokens)
}

func normalizeAPITokens(tokens map[string]string) map[string]string {
	normalized := make(map[string]string, len(tokens))
	for token, role := range tokens {
		role = strings.ToLower(strings.TrimSpace(role))
		if token != "" && (role == "viewer" || role == "analyst" || role == "admin") {
			normalized[token] = role
		}
	}
	return normalized
}

// SetAPITokenLoader supplies a fresh token mapping from the process
// environment or another external source. The loader must not persist or log
// token values. It exists so an admin can apply an operator-managed rotation
// without restarting a local dashboard server.
func (s *Server) SetAPITokenLoader(loader func() (map[string]string, error)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.apiTokenLoader = loader
}

func (s *Server) SetTLS(certFile, keyFile string) {
	s.certFile = certFile
	s.keyFile = keyFile
}

func (s *Server) IdentityManager() *IdentityManager {
	return s.identityMgr
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if s.listenAddress == "" {
		s.listenAddress = "127.0.0.1"
	}
	if ip := net.ParseIP(s.listenAddress); s.listenAddress != "localhost" && (ip == nil || !ip.IsLoopback()) && (s.certFile == "" || s.keyFile == "") {
		return fmt.Errorf("a non-loopback coordinator listener requires TLS certificate and key files")
	}
	mux := http.NewServeMux()

	// REST Endpoints
	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/openapi.json", s.handleOpenAPISpec)
	mux.HandleFunc("/api/v1/integrations", s.handleIntegrations)
	mux.HandleFunc("/api/v1/capabilities", s.handleCapabilities)
	mux.HandleFunc("/api/v1/auth/token", s.handleAuthToken)
	mux.HandleFunc("/api/v1/auth/reload", s.handleReloadAPITokens)
	mux.HandleFunc("/api/v1/audit", s.handleAPIAudit)
	mux.HandleFunc("/api/v1/distributed/status", s.handleDistributedStatus)
	mux.HandleFunc("/api/v1/distributed/agent/heartbeat", s.handleDistributedAgentHeartbeat)
	mux.HandleFunc("/api/v1/distributed/agent/lease", s.handleDistributedAgentLease)
	mux.HandleFunc("/api/v1/distributed/agent/evidence", s.handleDistributedAgentEvidence)
	mux.HandleFunc("/api/v1/distributed/agent/complete", s.handleDistributedAgentComplete)
	mux.HandleFunc("/api/v1/dashboard/snapshot", s.handleDashboardSnapshot)
	mux.HandleFunc("/api/v1/engagement/plan", s.handleEngagementPlan)
	mux.HandleFunc("/api/v1/engagements", s.handleEngagements)
	mux.HandleFunc("/api/v1/scans", s.handleScans)
	mux.HandleFunc("/api/v1/scans/run", s.handleRunScan)
	mux.HandleFunc("/api/v1/scans/pause", s.handlePauseScan)
	mux.HandleFunc("/api/v1/scans/resume", s.handleResumeScan)
	mux.HandleFunc("/api/v1/metrics", s.handleMetrics)
	mux.HandleFunc("/api/v1/logs/stream", s.handleLiveLogs)
	mux.HandleFunc("/api/v1/assets", s.handleAssets)
	mux.HandleFunc("/api/v1/findings", s.handleFindings)
	mux.HandleFunc("/api/v1/findings/stream", s.handleFindingStream)
	mux.HandleFunc("/api/v1/findings/review", s.handleFindingReview)
	mux.HandleFunc("/api/v1/findings/assign", s.handleFindingAssign)
	mux.HandleFunc("/api/v1/findings/audit", s.handleFindingAudit)
	mux.HandleFunc("/api/v1/events", s.handleEvents)
	mux.HandleFunc("/api/v1/graph", s.handleGraph)
	mux.HandleFunc("/api/v1/graph/interactive", s.handleInteractiveGraph)
	mux.HandleFunc("/api/v1/graph/expand", s.handleGraphExpand)
	mux.HandleFunc("/api/v1/neo4j/graph", s.handleNeo4jGraph)
	mux.HandleFunc("/api/v1/search", s.handleSearch)
	mux.HandleFunc("/api/v1/screenshots", s.handleScreenshots)
	mux.HandleFunc("/api/v1/screenshots/", s.handleScreenshotContent)
	mux.HandleFunc("/api/v1/saved-queries", s.handleSavedQueries)
	mux.HandleFunc("/api/v1/timeline", s.handleTimeline)
	mux.HandleFunc("/api/v1/drift", s.handleDrift)
	mux.HandleFunc("/api/v1/reports/changes", s.handleChangeReports)
	mux.HandleFunc("/api/v1/knowledge-graph", s.handleKnowledgeGraph)
	mux.HandleFunc("/api/v1/knowledge-graph/query", s.handleKnowledgeGraphQuery)
	mux.HandleFunc("/", s.handleDashboard)

	// WebSocket Event Stream
	mux.HandleFunc("/api/v1/events/ws", s.handleWebSocketEvents)

	// GraphQL API
	mux.HandleFunc("/query", s.handleGraphQL)

	// Identity & Tenancy
	if s.identityMgr != nil {
		s.identityMgr.RegisterRoutes(mux)
	}

	// Security & Audit Middleware Chain
	// Keep audit after authentication so it can use the server-assigned principal,
	// but before authorization so rejected mutations are recorded as well.
	handler := s.rateLimiterMiddleware(s.securityHeadersMiddleware(s.authMiddleware(s.auditLoggerMiddleware(s.rbacMiddleware(mux)))))

	s.httpSrv = &http.Server{
		Addr:         net.JoinHostPort(s.listenAddress, strconv.Itoa(s.port)),
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
		if r.URL.Path == "/api/v1/health" || r.URL.Path == "/api/v1/auth/token" || strings.HasPrefix(r.URL.Path, "/api/v1/distributed/agent/") {
			next.ServeHTTP(w, r)
			return
		}

		if s.apiKey != "" || len(s.apiTokens) > 0 {
			key := r.Header.Get("X-API-Key")
			if key == "" {
				authHeader := r.Header.Get("Authorization")
				if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
					key = authHeader[7:]
				}
			}
			principal, ok := s.principalForToken(key)
			if !ok {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), apiPrincipalContextKey{}, principal))
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) authenticateDistributedAgentRequest(w http.ResponseWriter, r *http.Request) (string, []byte, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return "", nil, false
	}
	const maxAgentRequestBytes = 16 << 20
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAgentRequestBytes+1))
	if err != nil || len(body) > maxAgentRequestBytes {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return "", nil, false
	}
	agentID := r.Header.Get("X-Enumscan-Agent-ID")
	timestamp := r.Header.Get("X-Enumscan-Timestamp")
	nonce := r.Header.Get("X-Enumscan-Nonce")
	signature := r.Header.Get("X-Enumscan-Signature")
	message := store.DistributedAgentMessage(r.Method, r.URL.EscapedPath(), timestamp, nonce, body)
	if err := s.db.AuthenticateDistributedAgent(r.Context(), agentID, timestamp, nonce, signature, message); err != nil {
		http.Error(w, `{"error":"agent authentication failed"}`, http.StatusUnauthorized)
		return "", nil, false
	}
	return agentID, body, true
}

func (s *Server) handleDistributedAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	agentID, _, ok := s.authenticateDistributedAgentRequest(w, r)
	if !ok {
		return
	}
	if err := s.db.HeartbeatDistributedAgent(r.Context(), agentID); err != nil {
		http.Error(w, `{"error":"heartbeat failed"}`, http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "online"})
}

func (s *Server) handleDistributedAgentLease(w http.ResponseWriter, r *http.Request) {
	agentID, body, ok := s.authenticateDistributedAgentRequest(w, r)
	if !ok {
		return
	}
	var request struct {
		LeaseSeconds int `json:"lease_seconds"`
	}
	if len(body) > 0 && json.Unmarshal(body, &request) != nil {
		http.Error(w, `{"error":"invalid lease request"}`, http.StatusBadRequest)
		return
	}
	if request.LeaseSeconds == 0 {
		request.LeaseSeconds = 60
	}
	job, err := s.db.LeaseDistributedScanJob(r.Context(), agentID, time.Duration(request.LeaseSeconds)*time.Second)
	if errors.Is(err, store.ErrNoDistributedJob) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		http.Error(w, `{"error":"lease failed"}`, http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(job)
}

func (s *Server) handleDistributedAgentComplete(w http.ResponseWriter, r *http.Request) {
	agentID, body, ok := s.authenticateDistributedAgentRequest(w, r)
	if !ok {
		return
	}
	var request struct {
		JobID  string `json:"job_id"`
		Status string `json:"status"`
	}
	if json.Unmarshal(body, &request) != nil || request.JobID == "" {
		http.Error(w, `{"error":"invalid completion request"}`, http.StatusBadRequest)
		return
	}
	if err := s.db.CompleteDistributedScanJob(r.Context(), request.JobID, agentID, request.Status); err != nil {
		http.Error(w, `{"error":"completion rejected"}`, http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": request.Status})
}

func (s *Server) handleDistributedAgentEvidence(w http.ResponseWriter, r *http.Request) {
	agentID, body, ok := s.authenticateDistributedAgentRequest(w, r)
	if !ok {
		return
	}
	var envelope models.DistributedEvidence
	if json.Unmarshal(body, &envelope) != nil || envelope.JobID == "" {
		http.Error(w, `{"error":"invalid evidence envelope"}`, http.StatusBadRequest)
		return
	}
	if err := s.db.IngestDistributedEvidence(r.Context(), agentID, envelope); err != nil {
		http.Error(w, `{"error":"evidence rejected"}`, http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
}

func (s *Server) rbacMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ := r.Context().Value(apiPrincipalContextKey{}).(apiPrincipal)
		role := principal.role
		if role == "viewer" && (r.Method == http.MethodPost || r.Method == http.MethodDelete || r.Method == http.MethodPut) {
			http.Error(w, `{"error":"forbidden: viewer role has read-only access"}`, http.StatusForbidden)
			return
		}
		if role == "analyst" && r.Method == http.MethodDelete {
			http.Error(w, `{"error":"forbidden: analyst role cannot delete"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) principalForToken(candidate string) (apiPrincipal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.apiKey != "" && subtle.ConstantTimeCompare([]byte(candidate), []byte(s.apiKey)) == 1 {
		return apiPrincipal{role: "admin", actor: tokenActor(candidate)}, true
	}
	for token, role := range s.apiTokens {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(token)) == 1 {
			return apiPrincipal{role: role, actor: tokenActor(candidate)}, true
		}
	}
	return apiPrincipal{}, false
}

func tokenActor(token string) string {
	digest := sha256.Sum256([]byte(token))
	return "api-token:" + fmt.Sprintf("%x", digest[:6])
}

func (s *Server) handleAuthToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	// The old endpoint minted bearer-looking strings without authenticating a
	// caller or storing/validating them. Do not expose a counterfeit token
	// issuer; production deployments need an OIDC/session implementation.
	http.Error(w, `{"error":"token issuance is not configured; use an API key or configure an external identity provider"}`, http.StatusNotImplemented)
}

// handleReloadAPITokens applies a replacement, externally supplied token map.
// It never returns token values, keeps the existing map on error, and requires
// an already authenticated admin principal.
func (s *Server) handleReloadAPITokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	principal, _ := r.Context().Value(apiPrincipalContextKey{}).(apiPrincipal)
	if principal.role != "admin" {
		http.Error(w, `{"error":"forbidden: admin role is required"}`, http.StatusForbidden)
		return
	}
	s.mu.RLock()
	loader := s.apiTokenLoader
	s.mu.RUnlock()
	if loader == nil {
		http.Error(w, `{"error":"token reload is not configured"}`, http.StatusPreconditionFailed)
		return
	}
	tokens, err := loader()
	if err != nil {
		log.Printf("[AUTH] token reload rejected: %v", err)
		http.Error(w, `{"error":"token reload rejected"}`, http.StatusPreconditionFailed)
		return
	}
	tokens = normalizeAPITokens(tokens)
	if len(tokens) == 0 {
		http.Error(w, `{"error":"token reload produced no tokens"}`, http.StatusPreconditionFailed)
		return
	}
	s.SetAPITokens(tokens)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "reloaded", "token_count": len(tokens)})
}

func (s *Server) handleAPIAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.db == nil {
		http.Error(w, `{"error":"audit store unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	s.mu.RLock()
	authEnabled := s.apiKey != "" || len(s.apiTokens) > 0
	s.mu.RUnlock()
	if authEnabled {
		principal, _ := r.Context().Value(apiPrincipalContextKey{}).(apiPrincipal)
		if principal.role != "admin" {
			http.Error(w, `{"error":"forbidden: admin role is required"}`, http.StatusForbidden)
			return
		}
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := s.db.RecentAPIAudit(r.Context(), limit)
	if err != nil {
		http.Error(w, `{"error":"audit query failed"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(entries)
}

// handleDistributedStatus exposes only the local coordinator ledger. It does
// not send work to an agent or disclose target configuration. As with audit
// records, a configured API token setup restricts it to admins.
func (s *Server) handleDistributedStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if s.db == nil {
		http.Error(w, `{"error":"database unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	s.mu.RLock()
	authEnabled := s.apiKey != "" || len(s.apiTokens) > 0
	s.mu.RUnlock()
	if authEnabled {
		principal, _ := r.Context().Value(apiPrincipalContextKey{}).(apiPrincipal)
		if principal.role != "admin" {
			http.Error(w, `{"error":"admin role required"}`, http.StatusForbidden)
			return
		}
	}
	limit := 50
	if rawLimit := r.URL.Query().Get("limit"); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed < 1 || parsed > 200 {
			http.Error(w, `{"error":"limit must be between 1 and 200"}`, http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	status, err := s.db.DistributedCoordinatorStatus(r.Context(), limit)
	if err != nil {
		http.Error(w, `{"error":"distributed coordinator status unavailable"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}

// handleIntegrations returns the same offline preflight used by `enumscan
// doctor`. It never contacts providers or serializes credential values.
func (s *Server) handleIntegrations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(modules.DiagnosePassiveIntel(s.cfg.PassiveIntel, os.LookupEnv))
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(capability.Current())
}

func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
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
		if r.Method == http.MethodGet || r.Method == http.MethodHead || s.db == nil {
			next.ServeHTTP(w, r)
			return
		}
		writer := &auditResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(writer, r)
		principal, _ := r.Context().Value(apiPrincipalContextKey{}).(apiPrincipal)
		actor, role := principal.actor, principal.role
		if actor == "" {
			actor, role = "local-unauthenticated", "local"
		}
		if err := s.db.RecordAPIAudit(r.Context(), models.APIAuditEntry{Actor: actor, Role: role, Action: r.Method + " " + r.URL.Path, ScanID: r.URL.Query().Get("scan_id"), Status: writer.status}); err != nil {
			log.Printf("[AUDIT] persist %s %s failed: %v", r.Method, r.URL.Path, err)
		}
	})
}

type auditResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *auditResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
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

// engagementPlanRequest deliberately contains only the information needed to
// create a new safe plan. It cannot enable active testing, attach credentials,
// or alter the running server's own scope.
type engagementPlanRequest struct {
	Target        string `json:"target"`
	Profile       string `json:"profile"`
	Authorization string `json:"authorization"`
	Filename      string `json:"filename"`
}

// handleEngagementPlan renders a downloadable YAML plan. It does not write a
// file on the coordinator, so browser users retain review and storage control.
func (s *Server) handleEngagementPlan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	s.mu.RLock()
	requireAuth := s.cfg.API.RequireAuth
	s.mu.RUnlock()
	if requireAuth {
		principal, _ := r.Context().Value(apiPrincipalContextKey{}).(apiPrincipal)
		if principal.role != "admin" {
			http.Error(w, `{"error":"forbidden: admin role is required to create engagement configurations"}`, http.StatusForbidden)
			return
		}
	}
	var request engagementPlanRequest
	decoder := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, `{"error":"target, profile, and written authorization are required"}`, http.StatusBadRequest)
		return
	}
	input := config.EngagementInput{
		Target: request.Target, Profile: request.Profile, Authorization: request.Authorization,
	}
	content, err := config.RenderEngagementConfig(input)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	filename := "enumscan-engagement.yaml"
	if rawFilename := strings.TrimSpace(request.Filename); rawFilename != "" {
		base := filepath.Base(rawFilename)
		if base != "" && base != "." && base != "/" {
			if !strings.HasSuffix(base, ".yaml") && !strings.HasSuffix(base, ".yml") {
				base += ".yaml"
			}
			filename = base
		}
	}
	preview, _ := config.PreviewEngagementPlan(input, "data/enumscan.sqlite")
	previewJSON, _ := json.Marshal(preview)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"filename": filename,
		"config":   string(content),
		"notice":   "Review the downloaded config before use. It is locked to one authorized scope and safe enumeration settings.",
		"preview":  string(previewJSON),
	})
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

	s.mu.RLock()
	scanCfg := s.cfg
	s.mu.RUnlock()
	if strings.TrimSpace(scanCfg.Scope.Authorization) == "" {
		http.Error(w, `{"error":"server scan configuration is missing scope.authorization"}`, http.StatusPreconditionFailed)
		return
	}
	if !scope.New(scanCfg.Scope.AllowedTargets).Allowed(target) {
		http.Error(w, `{"error":"target is outside the server's authorized scope"}`, http.StatusForbidden)
		return
	}
	scanCfg.Scan.Targets = []string{target}
	if profile != "" {
		var err error
		scanCfg, err = config.ApplyRequestedProfile(scanCfg, profile)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
			return
		}
		profile = scanCfg.Scan.Profile
	}

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
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		runs, err := s.db.ScanRuns(r.Context(), limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(runs)
		return
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

	if err := s.db.UpdateScanStatus(r.Context(), req.ScanID, "paused"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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

	if err := s.db.UpdateScanStatus(r.Context(), req.ScanID, "running"); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.BroadcastEvent(models.Event{ScanID: req.ScanID, Type: "scan.resumed", Target: req.ScanID})
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "running", "scan_id": req.ScanID})
}

type liveMetricsResponse struct {
	ScanID              string                   `json:"scan_id"`
	Status              string                   `json:"status"`
	Assets              int                      `json:"assets"`
	Findings            int                      `json:"findings"`
	Events              int                      `json:"events"`
	CompletedRuns       int                      `json:"completed_runs"`
	FailedRuns          int                      `json:"failed_runs"`
	ProgressPercent     *float64                 `json:"progress_percent,omitempty"`
	ThroughputPerMinute float64                  `json:"throughput_per_minute"`
	QueueETASeconds     *int64                   `json:"queue_eta_seconds,omitempty"`
	QueueETANote        string                   `json:"queue_eta_note,omitempty"`
	Runtime             *models.ScanRuntimeStats `json:"runtime,omitempty"`
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		scanID = "default"
	}
	metrics, err := s.db.ScanMetrics(r.Context(), scanID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			metrics.Status = "unknown"
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	response := liveMetricsResponse{
		ScanID: scanID, Status: metrics.Status, Assets: metrics.Assets,
		Findings: metrics.Findings, Events: metrics.Events,
		CompletedRuns: metrics.CompletedRuns, FailedRuns: metrics.FailedRuns,
		ThroughputPerMinute: metrics.ThroughputPerMinute,
	}
	if metrics.Status == "completed" || metrics.Status == "failed" {
		progress := 100.0
		response.ProgressPercent = &progress
	}
	if runtime, err := s.db.ScanRuntimeStats(r.Context(), scanID); err == nil {
		response.Runtime = &runtime
		response.QueueETASeconds = queueETA(metrics, runtime, time.Now())
		if response.QueueETASeconds != nil {
			response.QueueETANote = "estimate for currently queued work; newly discovered events can extend it"
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(response)
}

// queueETA estimates only the work visible in a persisted scheduler snapshot.
// It is intentionally omitted until at least one event has completed, and it
// does not pretend to know future events produced by active modules.
func queueETA(metrics store.ScanMetrics, runtime models.ScanRuntimeStats, now time.Time) *int64 {
	if metrics.Status != "running" || runtime.CompletedEvents < 1 || metrics.StartedAt.IsZero() {
		return nil
	}
	elapsed := now.Sub(metrics.StartedAt)
	if elapsed < time.Second {
		return nil
	}
	perSecond := float64(runtime.CompletedEvents) / elapsed.Seconds()
	if perSecond <= 0 {
		return nil
	}
	remaining := int64(runtime.QueueHigh + runtime.QueueNormal + runtime.QueueLow + runtime.ActiveWorkers)
	if remaining < 1 {
		return nil
	}
	seconds := int64(math.Ceil(float64(remaining) / perSecond))
	if seconds < 1 || seconds > 24*60*60 {
		return nil
	}
	return &seconds
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

	// EventSource reconnects after this bounded response. Every item is derived
	// from a persisted module run; no synthetic attachment or progress record is
	// emitted when the scan has produced no work yet.
	_, _ = fmt.Fprint(w, "retry: 1000\n\n")
	logs, err := s.db.RecentModuleRunLogs(r.Context(), scanID, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, entry := range logs {
		level := "INFO"
		if entry.Status == "failed" {
			level = "ERROR"
		}
		message := fmt.Sprintf("%s %s for %s (%d ms)", entry.Module, entry.Status, entry.Target, entry.DurationMS)
		if entry.Error != "" {
			message += ": " + entry.Error
		}
		payload, err := json.Marshal(map[string]any{
			"id": entry.ID, "time": entry.CreatedAt.UTC().Format(time.RFC3339),
			"level": level, "msg": message, "run": entry,
		})
		if err == nil {
			_, _ = fmt.Fprintf(w, "data: %s\n\n", payload)
		}
	}
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

// handleFindingStream emits only findings already persisted for the selected
// scan. The bounded response lets EventSource reconnect for polling without
// inventing progress or exposing in-memory, uncommitted module output.
func (s *Server) handleFindingStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		http.Error(w, `{"error":"scan_id is required"}`, http.StatusBadRequest)
		return
	}
	findings, err := s.db.Findings(r.Context(), scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, _ = fmt.Fprint(w, "retry: 1000\n\n")
	for _, finding := range findings {
		payload, err := json.Marshal(finding)
		if err == nil {
			_, _ = fmt.Fprintf(w, "event: finding\ndata: %s\n\n", payload)
		}
	}
	flusher.Flush()
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

// handleNeo4jGraph retrieves a fixed, read-only graph for one scan from the
// operator-configured Neo4j instance. It is requested only by the dedicated
// dashboard view; arbitrary Cypher is intentionally unsupported.
func (s *Server) handleNeo4jGraph(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scanID := r.URL.Query().Get("scan_id")
	if scanID == "" {
		http.Error(w, `{"error":"scan_id is required"}`, http.StatusBadRequest)
		return
	}
	if s.cfg.Neo4j.URI == "" {
		http.Error(w, `{"error":"Neo4j synchronization is not configured"}`, http.StatusServiceUnavailable)
		return
	}
	password := os.Getenv(s.cfg.Neo4j.PasswordEnv)
	if password == "" {
		http.Error(w, `{"error":"Neo4j password environment variable is unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	graph, err := store.NewNeo4jStore(s.cfg.Neo4j.URI, s.cfg.Neo4j.Username, password).LoadScanGraph(r.Context(), scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
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
	Health       models.ScanHealth   `json:"health"`
	Assets       []models.Asset      `json:"assets"`
	Findings     []models.Finding    `json:"findings"`
	Events       []models.Event      `json:"events"`
	Screenshots  []models.Asset      `json:"screenshots"`
	Graph        models.AssetGraph   `json:"graph"`
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

// handleScreenshotContent serves only a previously verified screenshot asset.
// It verifies the configured artifact-root boundary and stored checksum again
// before responding, so an arbitrary database value cannot expose local files.
func (s *Server) handleScreenshotContent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/v1/screenshots/"), "/")
	if len(parts) != 2 || parts[1] != "content" {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || id < 1 {
		http.NotFound(w, r)
		return
	}
	asset, err := s.db.AssetByID(r.Context(), id)
	if err != nil || asset.Type != "screenshot" || !s.screenshotPathAllowed(asset.Value) {
		http.NotFound(w, r)
		return
	}
	expected := metadataValue(asset.Metadata, "sha256")
	checksum, err := screenshotChecksum(asset.Value)
	if err != nil || expected == "" || checksum != expected {
		http.Error(w, `{"error":"screenshot artifact is unavailable or failed integrity verification"}`, http.StatusGone)
		return
	}
	file, err := os.Open(asset.Value)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=60")
	http.ServeContent(w, r, filepath.Base(asset.Value), info.ModTime(), file)
}

func (s *Server) screenshotPathAllowed(path string) bool {
	root := s.cfg.HTTP.ScreenshotOutputDir
	if !filepath.IsAbs(root) || !filepath.IsAbs(path) {
		return false
	}
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func metadataValue(metadata, key string) string {
	for _, part := range strings.Split(metadata, ";") {
		name, value, ok := strings.Cut(part, "=")
		if ok && name == key {
			return value
		}
	}
	return ""
}

func screenshotChecksum(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > 10<<20 {
		return "", fmt.Errorf("screenshot file is outside permitted size bounds")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, (10<<20)+1)); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
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

func (s *Server) handleKnowledgeGraph(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scanID := r.URL.Query().Get("scan_id")
	filterType := r.URL.Query().Get("type")
	query := r.URL.Query().Get("q")

	engine := inventory.NewKnowledgeGraphEngine(s.db)
	graph, err := engine.BuildKnowledgeGraph(r.Context(), scanID, inventory.KnowledgeGraphOptions{
		FilterType: filterType,
		Query:      query,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(graph)
}

func (s *Server) handleKnowledgeGraphQuery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var opts inventory.KnowledgeGraphOptions
	if r.Method == http.MethodPost {
		_ = json.NewDecoder(r.Body).Decode(&opts)
	} else {
		opts.FilterType = r.URL.Query().Get("type")
		opts.Query = r.URL.Query().Get("q")
	}
	scanID := r.URL.Query().Get("scan_id")

	engine := inventory.NewKnowledgeGraphEngine(s.db)
	graph, err := engine.BuildKnowledgeGraph(r.Context(), scanID, opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(graph)
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
