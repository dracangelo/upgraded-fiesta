# Observability & Alerting Architecture

Enumscan provides enterprise observability exports designed for production monitoring, distributed tracing, and automated alert routing.

## 1. Prometheus / OpenMetrics Export

The API server exposes metrics formatted for Prometheus scraping at `GET /api/v1/metrics`.

### Key Metrics

| Metric | Type | Description |
| --- | --- | --- |
| `enumscan_scans_total{status="..."}` | Counter | Total completed, running, or failed scans |
| `enumscan_assets_discovered_total{type="..."}` | Counter | Discovered assets by classification type |
| `enumscan_findings_total{severity="..."}` | Counter | Findings identified by severity |
| `enumscan_events_total` | Counter | Total pipeline event envelopes processed |
| `enumscan_active_workers` | Gauge | Currently active worker goroutines |
| `enumscan_queue_depth` | Gauge | Number of distributed jobs pending execution |
| `enumscan_scan_duration_seconds` | Gauge | Average scan duration |
| `enumscan_error_rate_percentage` | Gauge | Pipeline error rate percentage |

### Prometheus Scrape Configuration

```yaml
scrape_configs:
  - job_name: 'enumscan'
    scrape_interval: 15s
    static_configs:
      - targets: ['127.0.0.1:8080']
    metrics_path: '/api/v1/metrics'
```

---

## 2. Distributed Tracing & W3C Trace Context

Enumscan supports W3C Trace Context (`traceparent` header) for end-to-end distributed correlation across distributed agents, coordinator, and backends.

- Standard format: `00-{trace_id}-{span_id}-{trace_flags}`
- Export format: Structured OpenTelemetry-compatible JSON spans capturing start/end timestamps, duration, attributes, and execution status.

---

## 3. Operator-Configured Alert Routing

The `AlertRouter` matches findings against operator rules with automated deduplication and cooldown enforcement.

```yaml
alert_rules:
  - id: "critical-findings"
    name: "Critical Vulnerability Discovered"
    min_severity: "critical"
    target_type: "webhook"
    target_url: "https://alerts.corp.internal/webhooks/security"
    cooldown: "1h"

  - id: "high-findings-slack"
    name: "High Severity SecOps Channel"
    min_severity: "high"
    target_type: "slack"
    target_url: "https://hooks.slack.com/services/..."
    cooldown: "30m"
```

---

## 4. Durable Event Subscriptions

Durable event subscriptions allow external automation to stream real-time events via Server-Sent Events (SSE) or WebSockets with buffer-overflow protection.
