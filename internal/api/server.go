package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

type Server struct {
	db        *store.SQLiteCLI
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
	mux.HandleFunc("/api/v1/assets", s.handleAssets)
	mux.HandleFunc("/api/v1/findings", s.handleFindings)

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
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) rateLimiterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		s.mu.Lock()
		last, exists := s.rateMap[ip]
		now := time.Now()
		if exists && now.Sub(last) < 10*time.Millisecond {
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
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
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
