package reporting

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"enumscan/internal/models"
)

func TestPrometheusMetricsExport(t *testing.T) {
	snap := ObservabilityMetricsSnapshot{
		ScansTotal: map[string]int64{
			"completed": 42,
			"failed":    2,
		},
		AssetsDiscovered: map[string]int64{
			"ipv4":   150,
			"domain": 30,
		},
		FindingsTotal: map[string]int64{
			"critical": 3,
			"high":     12,
		},
		EventsTotal:         1500,
		ActiveWorkers:       8,
		QueueDepth:          4,
		AverageDurationSec:  45.5,
		ErrorRatePercentage: 1.25,
	}

	metrics := ExportPrometheusMetrics(snap)

	if !strings.Contains(metrics, `enumscan_scans_total{status="completed"} 42`) {
		t.Errorf("expected scans_total completed metric: %s", metrics)
	}
	if !strings.Contains(metrics, `enumscan_assets_discovered_total{type="ipv4"} 150`) {
		t.Errorf("expected assets_discovered metric: %s", metrics)
	}
	if !strings.Contains(metrics, `enumscan_findings_total{severity="critical"} 3`) {
		t.Errorf("expected findings_total critical metric: %s", metrics)
	}
	if !strings.Contains(metrics, `enumscan_active_workers 8`) {
		t.Errorf("expected active_workers metric: %s", metrics)
	}
	if !strings.Contains(metrics, `enumscan_error_rate_percentage 1.25`) {
		t.Errorf("expected error_rate metric: %s", metrics)
	}
}

func TestW3CTraceContextAndJSONSpans(t *testing.T) {
	traceID, spanID, traceparent := GenerateTraceParent()

	if len(traceID) != 32 {
		t.Fatalf("expected 32-hex trace ID, got %s", traceID)
	}
	if len(spanID) != 16 {
		t.Fatalf("expected 16-hex span ID, got %s", spanID)
	}
	if !strings.HasPrefix(traceparent, "00-") || !strings.HasSuffix(traceparent, "-01") {
		t.Fatalf("invalid traceparent format: %s", traceparent)
	}

	spans := []Span{
		{
			TraceID:    traceID,
			SpanID:     spanID,
			Name:       "portscan.syn",
			StartTime:  time.Now().Add(-100 * time.Millisecond),
			EndTime:    time.Now(),
			DurationMS: 100,
			Attributes: map[string]string{"target": "10.0.0.1", "ports": "80,443"},
			Status:     "ok",
		},
	}

	rawJSON, err := ExportJSONTraces(spans)
	if err != nil {
		t.Fatalf("failed to serialize traces: %v", err)
	}

	var decoded []Span
	if err := json.Unmarshal(rawJSON, &decoded); err != nil || len(decoded) != 1 {
		t.Fatalf("failed to decode exported spans: %v", err)
	}
	if decoded[0].Name != "portscan.syn" || decoded[0].Attributes["target"] != "10.0.0.1" {
		t.Fatalf("unexpected decoded span: %#v", decoded[0])
	}
}

func TestAlertRouterWithSeverityAndCooldown(t *testing.T) {
	rules := []AlertRule{
		{
			ID:          "rule-crit",
			Name:        "Critical Alerts",
			MinSeverity: "critical",
			TargetType:  "webhook",
			TargetURL:   "https://alerts.invalid/crit",
			Cooldown:    1 * time.Hour,
		},
		{
			ID:          "rule-high",
			Name:        "High & Above Alerts",
			MinSeverity: "high",
			TargetType:  "slack",
			TargetURL:   "https://slack.invalid/high",
			Cooldown:    30 * time.Minute,
		},
	}

	router := NewAlertRouter(rules)

	lowFinding := models.Finding{
		Severity: "low",
		Asset:    "10.0.0.1",
		Title:    "Info Disclosure",
	}
	highFinding := models.Finding{
		Severity: "high",
		Asset:    "10.0.0.1",
		Title:    "Weak Ciphers",
	}
	critFinding := models.Finding{
		Severity: "critical",
		Asset:    "10.0.0.2",
		Title:    "RCE Exposure",
	}

	// 1. Low finding should match 0 rules
	results := router.RouteFinding(lowFinding)
	if len(results) != 0 {
		t.Fatalf("low finding should not trigger high/crit alerts, got %d results", len(results))
	}

	// 2. High finding should match rule-high only
	results = router.RouteFinding(highFinding)
	if len(results) != 1 || results[0].RuleID != "rule-high" || !results[0].Dispatched {
		t.Fatalf("high finding should trigger rule-high, got %#v", results)
	}

	// 3. Second immediate high finding with same title should be suppressed by cooldown
	results = router.RouteFinding(highFinding)
	if len(results) != 1 || results[0].Dispatched {
		t.Fatalf("duplicate finding should be suppressed by cooldown: %#v", results)
	}

	// 4. Critical finding matches both rules
	results = router.RouteFinding(critFinding)
	if len(results) != 2 {
		t.Fatalf("critical finding should trigger both rules, got %d", len(results))
	}
}

func TestDurableSubscriptionPublishAndDrop(t *testing.T) {
	mgr := NewEventSubscriptionManager()

	sub := mgr.Subscribe("scan-sub-test", 2)
	defer mgr.Unsubscribe(sub.ID)

	event1 := models.Event{ScanID: "scan-sub-test", Type: "asset_found", Target: "1.1.1.1"}
	event2 := models.Event{ScanID: "scan-sub-test", Type: "finding_identified", Target: "1.1.1.1"}
	event3 := models.Event{ScanID: "scan-sub-test", Type: "port_open", Target: "1.1.1.1"}

	mgr.Publish(event1)
	mgr.Publish(event2)
	// Buffer is full (size 2); event3 should drop without blocking publisher
	mgr.Publish(event3)

	received1 := <-sub.Buffer
	received2 := <-sub.Buffer

	if received1.Type != "asset_found" || received2.Type != "finding_identified" {
		t.Fatalf("unexpected events received: %#v %#v", received1, received2)
	}

	select {
	case extra := <-sub.Buffer:
		t.Fatalf("expected buffer overflow drop, got unexpected extra event: %#v", extra)
	default:
		// Succeeded in dropping without blocking
	}
}
