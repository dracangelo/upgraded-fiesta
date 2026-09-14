package reporting

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"enumscan/internal/models"
)

// ObservabilityMetricsSnapshot holds point-in-time metrics for Prometheus export.
type ObservabilityMetricsSnapshot struct {
	ScansTotal          map[string]int64 // by status: completed, failed, running
	AssetsDiscovered    map[string]int64 // by type: ip, domain, service
	FindingsTotal       map[string]int64 // by severity: critical, high, medium, low
	EventsTotal         int64
	ActiveWorkers       int
	QueueDepth          int
	AverageDurationSec  float64
	ErrorRatePercentage float64
}

// ExportPrometheusMetrics renders an OpenMetrics / Prometheus exposition text format document.
func ExportPrometheusMetrics(snap ObservabilityMetricsSnapshot) string {
	var b strings.Builder

	b.WriteString("# HELP enumscan_scans_total Total number of scans by terminal status.\n")
	b.WriteString("# TYPE enumscan_scans_total counter\n")
	for status, count := range snap.ScansTotal {
		fmt.Fprintf(&b, "enumscan_scans_total{status=%q} %d\n", status, count)
	}

	b.WriteString("# HELP enumscan_assets_discovered_total Total assets discovered by asset type.\n")
	b.WriteString("# TYPE enumscan_assets_discovered_total counter\n")
	for assetType, count := range snap.AssetsDiscovered {
		fmt.Fprintf(&b, "enumscan_assets_discovered_total{type=%q} %d\n", assetType, count)
	}

	b.WriteString("# HELP enumscan_findings_total Total findings identified by severity.\n")
	b.WriteString("# TYPE enumscan_findings_total counter\n")
	for severity, count := range snap.FindingsTotal {
		fmt.Fprintf(&b, "enumscan_findings_total{severity=%q} %d\n", severity, count)
	}

	b.WriteString("# HELP enumscan_events_total Total scan pipeline events processed.\n")
	b.WriteString("# TYPE enumscan_events_total counter\n")
	fmt.Fprintf(&b, "enumscan_events_total %d\n", snap.EventsTotal)

	b.WriteString("# HELP enumscan_active_workers Number of active worker goroutines.\n")
	b.WriteString("# TYPE enumscan_active_workers gauge\n")
	fmt.Fprintf(&b, "enumscan_active_workers %d\n", snap.ActiveWorkers)

	b.WriteString("# HELP enumscan_queue_depth Pending distributed jobs in queue.\n")
	b.WriteString("# TYPE enumscan_queue_depth gauge\n")
	fmt.Fprintf(&b, "enumscan_queue_depth %d\n", snap.QueueDepth)

	b.WriteString("# HELP enumscan_scan_duration_seconds Average scan duration in seconds.\n")
	b.WriteString("# TYPE enumscan_scan_duration_seconds gauge\n")
	fmt.Fprintf(&b, "enumscan_scan_duration_seconds %.2f\n", snap.AverageDurationSec)

	b.WriteString("# HELP enumscan_error_rate_percentage Pipeline error rate percentage.\n")
	b.WriteString("# TYPE enumscan_error_rate_percentage gauge\n")
	fmt.Fprintf(&b, "enumscan_error_rate_percentage %.2f\n", snap.ErrorRatePercentage)

	return b.String()
}

// Span represents a structured distributed trace span compatible with W3C Trace Context.
type Span struct {
	TraceID    string            `json:"trace_id"`
	SpanID     string            `json:"span_id"`
	ParentID   string            `json:"parent_id,omitempty"`
	Name       string            `json:"name"`
	StartTime  time.Time         `json:"start_time"`
	EndTime    time.Time         `json:"end_time"`
	DurationMS int64             `json:"duration_ms"`
	Attributes map[string]string `json:"attributes"`
	Status     string            `json:"status"` // "ok", "error"
}

// GenerateTraceParent returns a standard W3C traceparent header string.
func GenerateTraceParent() (traceID string, spanID string, traceparent string) {
	tBytes := make([]byte, 16)
	sBytes := make([]byte, 8)
	_, _ = rand.Read(tBytes)
	_, _ = rand.Read(sBytes)
	traceID = hex.EncodeToString(tBytes)
	spanID = hex.EncodeToString(sBytes)
	traceparent = fmt.Sprintf("00-%s-%s-01", traceID, spanID)
	return traceID, spanID, traceparent
}

// ExportJSONTraces serializes a collection of spans as structured JSON.
func ExportJSONTraces(spans []Span) ([]byte, error) {
	return json.MarshalIndent(spans, "", "  ")
}

// AlertRule defines an operator-configured route for notification upon finding discovery.
type AlertRule struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	MinSeverity string        `json:"min_severity"` // "critical", "high", "medium", "low"
	TargetType  string        `json:"target_type"`  // "webhook", "slack", "email"
	TargetURL   string        `json:"target_url"`
	Cooldown    time.Duration `json:"cooldown"`
}

// AlertDispatchResult tracks an evaluated and routed notification.
type AlertDispatchResult struct {
	RuleID    string    `json:"rule_id"`
	RuleName  string    `json:"rule_name"`
	TargetURL string    `json:"target_url"`
	FindingID string    `json:"finding_id"`
	Dispatched bool     `json:"dispatched"`
	Reason    string    `json:"reason,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// AlertRouter matches findings against configured rules with deduplication and cooldown.
type AlertRouter struct {
	mu        sync.Mutex
	rules     []AlertRule
	lastAlert map[string]time.Time // key: ruleID:asset:title -> timestamp
}

func NewAlertRouter(rules []AlertRule) *AlertRouter {
	return &AlertRouter{
		rules:     rules,
		lastAlert: make(map[string]time.Time),
	}
}

var severityRanks = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}

// RouteFinding evaluates a finding against alert rules and returns dispatch instructions.
func (r *AlertRouter) RouteFinding(f models.Finding) []AlertDispatchResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	var results []AlertDispatchResult
	now := time.Now().UTC()
	findingSevRank := severityRanks[strings.ToLower(f.Severity)]

	for _, rule := range r.rules {
		minRank := severityRanks[strings.ToLower(rule.MinSeverity)]
		if findingSevRank < minRank {
			continue
		}

		key := fmt.Sprintf("%s:%s:%s", rule.ID, f.Asset, f.Title)
		if last, exists := r.lastAlert[key]; exists && now.Sub(last) < rule.Cooldown {
			results = append(results, AlertDispatchResult{
				RuleID:     rule.ID,
				RuleName:   rule.Name,
				TargetURL:  rule.TargetURL,
				FindingID:  f.Title,
				Dispatched: false,
				Reason:     "cooldown active",
				Timestamp:  now,
			})
			continue
		}

		r.lastAlert[key] = now
		results = append(results, AlertDispatchResult{
			RuleID:     rule.ID,
			RuleName:   rule.Name,
			TargetURL:  rule.TargetURL,
			FindingID:  f.Title,
			Dispatched: true,
			Timestamp:  now,
		})
	}

	return results
}

// DurableSubscription provides a reliable, buffered queue for SSE/webhook subscribers.
type DurableSubscription struct {
	ID        string
	ScanID    string
	Buffer    chan models.Event
	CreatedAt time.Time
}

// EventSubscriptionManager handles event fan-out with buffer overflow drop protection.
type EventSubscriptionManager struct {
	mu            sync.RWMutex
	subscriptions map[string]*DurableSubscription
}

func NewEventSubscriptionManager() *EventSubscriptionManager {
	return &EventSubscriptionManager{
		subscriptions: make(map[string]*DurableSubscription),
	}
}

func (m *EventSubscriptionManager) Subscribe(scanID string, bufferSize int) *DurableSubscription {
	m.mu.Lock()
	defer m.mu.Unlock()

	if bufferSize <= 0 {
		bufferSize = 256
	}
	id := fmt.Sprintf("sub_%d", time.Now().UnixNano())
	sub := &DurableSubscription{
		ID:        id,
		ScanID:    scanID,
		Buffer:    make(chan models.Event, bufferSize),
		CreatedAt: time.Now().UTC(),
	}
	m.subscriptions[id] = sub
	return sub
}

func (m *EventSubscriptionManager) Unsubscribe(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if sub, ok := m.subscriptions[id]; ok {
		close(sub.Buffer)
		delete(m.subscriptions, id)
	}
}

func (m *EventSubscriptionManager) Publish(event models.Event) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, sub := range m.subscriptions {
		if sub.ScanID == "" || sub.ScanID == event.ScanID {
			select {
			case sub.Buffer <- event:
			default:
				// Non-blocking drop on slow consumer buffer overflow to preserve system stability
			}
		}
	}
}
