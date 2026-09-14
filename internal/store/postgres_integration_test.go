package store

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"enumscan/internal/models"
)

// TestPostgresCoreLifecycleIntegration is intentionally opt-in locally. CI
// supplies an ephemeral PostgreSQL instance through ENUMSCAN_POSTGRES_TEST_DSN
// so the production driver, SQL dialect, migration idempotence, and core
// evidence round trip are exercised together.
func TestPostgresCoreLifecycleIntegration(t *testing.T) {
	dsn := os.Getenv("ENUMSCAN_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("set ENUMSCAN_POSTGRES_TEST_DSN to run PostgreSQL integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	postgres := NewPostgresStore(dsn)
	if err := postgres.ConfigurePool(4, 2); err != nil {
		t.Fatal(err)
	}
	if err := postgres.OpenContext(ctx); err != nil {
		t.Fatal(err)
	}
	defer postgres.Close()
	if err := postgres.Migrate(ctx); err != nil {
		t.Fatalf("fresh PostgreSQL migration: %v", err)
	}
	if err := postgres.Migrate(ctx); err != nil {
		t.Fatalf("idempotent PostgreSQL migration: %v", err)
	}
	var migrationCount int
	if err := postgres.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM postgres_schema_migrations`).Scan(&migrationCount); err != nil || migrationCount != len(postgresMigrationNames) {
		t.Fatalf("PostgreSQL migration ledger: count=%d err=%v", migrationCount, err)
	}

	scanID := fmt.Sprintf("postgres-integration-%d", time.Now().UnixNano())
	queryName := "postgres-integration-query-" + scanID
	cacheKey := "postgres-integration-cache-" + scanID
	feedSource := "postgres-integration-feed-" + scanID
	suppressionFingerprint := "postgres-integration-suppression-" + scanID
	t.Cleanup(func() {
		for _, table := range []string{"events", "findings", "assets", "checkpoints", "module_runs", "port_observations", "scan_runtime_stats", "api_audit_records", "distributed_scan_jobs", "evidence_records", "scan_runs"} {
			_, _ = postgres.db.ExecContext(context.Background(), "DELETE FROM "+table+" WHERE scan_id=$1", scanID)
		}
		_, _ = postgres.db.ExecContext(context.Background(), `DELETE FROM saved_queries WHERE name=$1`, queryName)
		_, _ = postgres.db.ExecContext(context.Background(), `DELETE FROM operator_cache WHERE cache_key=$1`, cacheKey)
		_, _ = postgres.db.ExecContext(context.Background(), `DELETE FROM intelligence_feeds WHERE source=$1`, feedSource)
		_, _ = postgres.db.ExecContext(context.Background(), `DELETE FROM finding_suppressions WHERE fingerprint=$1`, suppressionFingerprint)
		_, _ = postgres.db.ExecContext(context.Background(), `DELETE FROM nvd_cves WHERE cve_id='CVE-2099-0001'`)
		_, _ = postgres.db.ExecContext(context.Background(), `DELETE FROM coordinator_leases WHERE cluster_id='ha-integration-cluster'`)
		_, _ = postgres.db.ExecContext(context.Background(), `DELETE FROM distributed_agent_nonces WHERE agent_id='postgres-integration-agent'`)
		_, _ = postgres.db.ExecContext(context.Background(), `DELETE FROM distributed_agents WHERE id='postgres-integration-agent'`)
	})
	if err := postgres.StartScan(ctx, scanID); err != nil {
		t.Fatalf("start scan: %v", err)
	}
	asset := models.Asset{ScanID: scanID, Type: "host", Value: "192.0.2.10", Parent: "integration", Metadata: "source=postgres-integration"}
	if err := postgres.AddAsset(ctx, asset); err != nil {
		t.Fatalf("add asset: %v", err)
	}
	finding := models.Finding{ScanID: scanID, Severity: "medium", Confidence: "high", Verification: "needs_review", Asset: asset.Value, Title: "PostgreSQL round-trip", Evidence: "bounded fixture", Remediation: "verify datastore", References: []string{"https://example.invalid/reference"}}
	if err := postgres.AddFinding(ctx, finding); err != nil {
		t.Fatalf("add finding: %v", err)
	}
	if _, err := postgres.AddEvent(ctx, models.Event{ScanID: scanID, Type: "integration", Target: asset.Value, Data: map[string]string{"source": "postgres"}}); err != nil {
		t.Fatalf("add event: %v", err)
	}
	if err := postgres.UpsertCheckpoint(ctx, models.Checkpoint{ScanID: scanID, Module: "integration", EventType: "fixture", Target: asset.Value, Status: "completed"}); err != nil {
		t.Fatalf("upsert checkpoint: %v", err)
	}
	if err := postgres.RecordModuleRun(ctx, models.ModuleRun{ScanID: scanID, Module: "integration", EventType: "fixture", Target: asset.Value, Status: "completed", Duration: time.Millisecond}); err != nil {
		t.Fatalf("record module run: %v", err)
	}
	if err := postgres.AddPortObservation(ctx, models.PortObservation{ScanID: scanID, Host: asset.Value, Port: 443, Protocol: "tcp", State: "open", LatencyMS: 1, Evidence: "integration", ObservedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("record port observation: %v", err)
	}
	if err := postgres.UpsertRuntimeStats(ctx, models.ScanRuntimeStats{ScanID: scanID, WorkerCapacity: 2, ActiveWorkers: 1, RunningModules: 1, EnqueuedEvents: 3, CompletedEvents: 2}); err != nil {
		t.Fatalf("upsert runtime stats: %v", err)
	}
	if err := postgres.SaveQuery(ctx, queryName, "host:192.0.2.10"); err != nil {
		t.Fatalf("save query: %v", err)
	}
	if err := postgres.RecordAPIAudit(ctx, models.APIAuditEntry{Actor: "integration", Role: "admin", Action: "test", ScanID: scanID, Status: 200}); err != nil {
		t.Fatalf("record API audit: %v", err)
	}
	firstLease, err := postgres.AcquireCoordinatorLease(ctx, "ha-integration-cluster", "ha-coordinator-a", 10*time.Second)
	if err != nil || firstLease.Epoch < 1 || postgres.RequireCoordinatorFence(ctx, firstLease) != nil {
		t.Fatalf("acquire coordinator lease: lease=%#v err=%v", firstLease, err)
	}
	if _, err := postgres.AcquireCoordinatorLease(ctx, "ha-integration-cluster", "ha-coordinator-b", 10*time.Second); !errors.Is(err, ErrCoordinatorStandby) {
		t.Fatalf("split-brain coordinator acquisition was accepted: %v", err)
	}
	if err := postgres.ReleaseCoordinatorLease(ctx, firstLease); err != nil {
		t.Fatalf("release coordinator lease: %v", err)
	}
	secondLease, err := postgres.AcquireCoordinatorLease(ctx, "ha-integration-cluster", "ha-coordinator-b", 10*time.Second)
	if err != nil || secondLease.Epoch <= firstLease.Epoch || postgres.RequireCoordinatorFence(ctx, firstLease) == nil {
		t.Fatalf("fenced coordinator failover: first=%#v second=%#v err=%v", firstLease, secondLease, err)
	}
	if _, err := postgres.RenewCoordinatorLease(ctx, secondLease, 10*time.Second); err != nil {
		t.Fatalf("renew coordinator lease: %v", err)
	}
	if err := postgres.PutCachedValue(ctx, cacheKey, "postgres-cache-value", time.Minute); err != nil {
		t.Fatalf("write operator cache: %v", err)
	}
	if value, ok, err := postgres.CachedValue(ctx, cacheKey); err != nil || !ok || value != "postgres-cache-value" {
		t.Fatalf("operator cache round trip: value=%q ok=%t err=%v", value, ok, err)
	}
	if err := postgres.RecordFeed(ctx, FeedMetadata{Source: feedSource, Provenance: "integration fixture"}, []byte("feed-body")); err != nil {
		t.Fatalf("record intelligence feed: %v", err)
	}
	if err := postgres.AddSuppression(ctx, suppressionFingerprint, "integration fixture", time.Now().UTC().Add(time.Minute)); err != nil {
		t.Fatalf("add suppression: %v", err)
	}
	if suppressed, err := postgres.IsSuppressed(ctx, suppressionFingerprint); err != nil || !suppressed {
		t.Fatalf("active suppression round trip: suppressed=%t err=%v", suppressed, err)
	}
	if err := postgres.AddSuppression(ctx, suppressionFingerprint, "expired integration fixture", time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatalf("expire suppression: %v", err)
	}
	if suppressed, err := postgres.IsSuppressed(ctx, suppressionFingerprint); err != nil || suppressed {
		t.Fatalf("expired suppression round trip: suppressed=%t err=%v", suppressed, err)
	}
	if err := postgres.RetainEvidence(ctx, scanID, "integration-fingerprint", "internal", []byte("evidence"), time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("retain evidence: %v", err)
	}
	if _, err := postgres.db.ExecContext(ctx, `INSERT INTO nvd_cves(cve_id,cwe_id,cvss,epss,kev,description,cpe_configurations) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(cve_id) DO UPDATE SET cpe_configurations=EXCLUDED.cpe_configurations`, "CVE-2099-0001", "CWE-1", 7.5, 0.2, true, "integration fixture", "target=cpe:2.3:a:enumscan:fixture:1.0"); err != nil {
		t.Fatalf("seed vulnerability intelligence: %v", err)
	}
	if records, err := postgres.VulnerabilitiesForCPE(ctx, "cpe:2.3:a:enumscan:fixture:1.0"); err != nil || len(records) == 0 || records[0].CVE != "CVE-2099-0001" {
		t.Fatalf("vulnerability intelligence round trip: records=%#v err=%v", records, err)
	}
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 1
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if _, err := postgres.RegisterDistributedAgent(ctx, "postgres-integration-agent", base64.RawStdEncoding.EncodeToString(publicKey)); err != nil {
		t.Fatalf("register distributed agent: %v", err)
	}
	if err := postgres.HeartbeatDistributedAgent(ctx, "postgres-integration-agent"); err != nil {
		t.Fatalf("heartbeat distributed agent: %v", err)
	}
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := "postgres-integration-nonce-0001"
	message := DistributedAgentMessage("POST", "/integration", timestamp, nonce, []byte("fixture"))
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	if err := postgres.AuthenticateDistributedAgent(ctx, "postgres-integration-agent", timestamp, nonce, signature, message); err != nil {
		t.Fatalf("authenticate distributed agent: %v", err)
	}
	if err := postgres.AuthenticateDistributedAgent(ctx, "postgres-integration-agent", timestamp, nonce, signature, message); err == nil {
		t.Fatal("replayed distributed-agent nonce was accepted")
	}
	job, err := postgres.EnqueueDistributedScanJob(ctx, scanID, "integration-authorization", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("enqueue distributed job: %v", err)
	}
	if leased, err := postgres.LeaseDistributedScanJob(ctx, "postgres-integration-agent", time.Minute); err != nil || leased.ID != job.ID || leased.LeaseOwner != "postgres-integration-agent" {
		t.Fatalf("lease distributed job: job=%#v err=%v", leased, err)
	}
	if status, err := postgres.DistributedCoordinatorStatus(ctx, 10); err != nil || !containsDistributedJob(status.Jobs, job.ID) || !containsDistributedAgent(status.Agents, "postgres-integration-agent") {
		t.Fatalf("distributed coordinator status: status=%#v err=%v", status, err)
	}
	distributedAsset := models.Asset{ScanID: scanID, Type: "service", Value: "https://192.0.2.10:8443", Parent: asset.Value, Metadata: "source=distributed-agent"}
	distributedFinding := models.Finding{ScanID: scanID, Severity: "low", Confidence: "medium", Asset: distributedAsset.Value, Title: "Distributed PostgreSQL round-trip", Evidence: "leased fixture", References: []string{"https://example.invalid/distributed"}}
	distributedEvent := models.Event{ScanID: scanID, Type: "distributed-integration", Target: distributedAsset.Value, Data: map[string]string{"source": "distributed-agent"}}
	if err := postgres.IngestDistributedEvidence(ctx, "postgres-integration-agent", models.DistributedEvidence{
		JobID:    job.ID,
		Assets:   []models.Asset{distributedAsset},
		Findings: []models.Finding{distributedFinding},
		Events:   []models.Event{distributedEvent},
	}); err != nil {
		t.Fatalf("ingest distributed evidence: %v", err)
	}
	if err := postgres.CompleteDistributedScanJob(ctx, job.ID, "postgres-integration-agent", "completed"); err != nil {
		t.Fatalf("complete distributed job: %v", err)
	}
	if checkpoint, err := postgres.CheckpointStatus(ctx, scanID, "integration", "fixture", asset.Value); err != nil || checkpoint != "completed" {
		t.Fatalf("checkpoint round trip: status=%q err=%v", checkpoint, err)
	}

	assets, err := postgres.Assets(ctx, scanID)
	if err != nil || len(assets) != 2 {
		t.Fatalf("asset round trip: assets=%#v err=%v", assets, err)
	}
	assetValues := map[string]bool{}
	for _, persisted := range assets {
		assetValues[persisted.Value] = true
	}
	if !assetValues[asset.Value] || !assetValues[distributedAsset.Value] {
		t.Fatalf("asset values were not persisted: assets=%#v", assets)
	}
	findings, err := postgres.Findings(ctx, scanID)
	if err != nil || len(findings) != 2 {
		t.Fatalf("finding round trip: findings=%#v err=%v", findings, err)
	}
	findingVerification := map[string]string{}
	for _, persisted := range findings {
		findingVerification[persisted.Title] = persisted.Verification
	}
	if findingVerification[finding.Title] != "needs_review" || findingVerification[distributedFinding.Title] != "confirmed" {
		t.Fatalf("finding verification was not persisted: findings=%#v", findings)
	}
	events, err := postgres.Events(ctx, scanID)
	if err != nil || len(events) != 2 {
		t.Fatalf("event round trip: events=%#v err=%v", events, err)
	}
	eventSources := map[string]string{}
	for _, persisted := range events {
		eventSources[persisted.Type] = persisted.Data["source"]
	}
	if eventSources["integration"] != "postgres" || eventSources["distributed-integration"] != "distributed-agent" {
		t.Fatalf("event values were not persisted: events=%#v", events)
	}
	if results, err := postgres.SearchCategorized(ctx, scanID, "distributed-agent", "global"); err != nil || len(results.Assets) != 1 || len(results.Findings) != 0 {
		t.Fatalf("categorized search round trip: results=%#v err=%v", results, err)
	}
	for _, persisted := range assets {
		if persisted.Value == asset.Value {
			if got, err := postgres.AssetByID(ctx, persisted.ID); err != nil || got.Value != asset.Value {
				t.Fatalf("asset by ID round trip: asset=%#v err=%v", got, err)
			}
			break
		}
	}
	temporaryAsset := models.Asset{ScanID: scanID, Type: "temporary", Value: "remove-me", Parent: "integration"}
	if err := postgres.AddAsset(ctx, temporaryAsset); err != nil {
		t.Fatalf("add temporary asset: %v", err)
	}
	assets, err = postgres.Assets(ctx, scanID)
	if err != nil {
		t.Fatalf("list temporary asset: %v", err)
	}
	for _, persisted := range assets {
		if persisted.Value == temporaryAsset.Value {
			if err := postgres.DeleteAssets(ctx, []int64{persisted.ID}); err != nil {
				t.Fatalf("delete temporary asset: %v", err)
			}
		}
	}
	if err := postgres.FinishScan(ctx, scanID, "completed", ""); err != nil {
		t.Fatalf("finish scan: %v", err)
	}
	if health, err := postgres.ScanHealth(ctx, scanID); err != nil || !health.Healthy || health.CompletedRuns != 1 {
		t.Fatalf("scan health round trip: health=%#v err=%v", health, err)
	}
	if metrics, err := postgres.ScanMetrics(ctx, scanID); err != nil || metrics.Assets != 2 || metrics.Findings != 2 || metrics.Events != 2 || metrics.CompletedRuns != 1 {
		t.Fatalf("scan metrics round trip: metrics=%#v err=%v", metrics, err)
	}
	if stats, err := postgres.ScanRuntimeStats(ctx, scanID); err != nil || stats.WorkerCapacity != 2 || stats.CompletedEvents != 2 {
		t.Fatalf("runtime stats round trip: stats=%#v err=%v", stats, err)
	}
	if status, err := postgres.GetScanStatus(ctx, scanID); err != nil || status != "completed" {
		t.Fatalf("scan status round trip: status=%q err=%v", status, err)
	}
	runs, err := postgres.ScanRuns(ctx, 1)
	if err != nil || len(runs) != 1 || runs[0].ScanID != scanID || runs[0].AssetCount != 2 || runs[0].FindingCount != 2 || runs[0].EventCount != 2 {
		t.Fatalf("scan history round trip: runs=%#v err=%v", runs, err)
	}
	if queries, err := postgres.SavedQueries(ctx); err != nil || !containsSavedQuery(queries, queryName) {
		t.Fatalf("saved query round trip: queries=%#v err=%v", queries, err)
	}
	if logs, err := postgres.RecentModuleRunLogs(ctx, scanID, 10); err != nil || len(logs) != 1 || logs[0].Module != "integration" {
		t.Fatalf("module logs round trip: logs=%#v err=%v", logs, err)
	}
	if audits, err := postgres.RecentAPIAudit(ctx, 10); err != nil || len(audits) != 1 || audits[0].Actor != "integration" {
		t.Fatalf("API audit round trip: entries=%#v err=%v", audits, err)
	}
}

func containsDistributedJob(jobs []models.DistributedScanJob, jobID string) bool {
	for _, job := range jobs {
		if job.ID == jobID {
			return true
		}
	}
	return false
}

func containsDistributedAgent(agents []models.DistributedAgent, agentID string) bool {
	for _, agent := range agents {
		if agent.ID == agentID {
			return true
		}
	}
	return false
}

func containsSavedQuery(queries []models.SavedQuery, name string) bool {
	for _, query := range queries {
		if query.Name == name {
			return true
		}
	}
	return false
}

func TestPostgresEncryptedEvidenceIntegration(t *testing.T) {
	dsn := os.Getenv("ENUMSCAN_POSTGRES_TEST_DSN")
	if dsn == "" {
		t.Skip("set ENUMSCAN_POSTGRES_TEST_DSN to run PostgreSQL integration tests")
	}
	key := make([]byte, 32)
	key[0] = 7
	postgres, err := NewEncryptedPostgresStore(dsn, key)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := postgres.OpenContext(ctx); err != nil {
		t.Fatal(err)
	}
	defer postgres.Close()
	if err := postgres.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	scanID := fmt.Sprintf("postgres-encryption-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = postgres.db.ExecContext(context.Background(), `DELETE FROM assets WHERE scan_id=$1`, scanID)
		_, _ = postgres.db.ExecContext(context.Background(), `DELETE FROM scan_runs WHERE scan_id=$1`, scanID)
	})
	if err := postgres.StartScan(ctx, scanID); err != nil {
		t.Fatal(err)
	}
	asset := models.Asset{ScanID: scanID, Type: "host", Value: "private-postgres.example", Parent: "encrypted-fixture", Metadata: "sensitive=true"}
	if err := postgres.AddAsset(ctx, asset); err != nil {
		t.Fatal(err)
	}
	var storedValue string
	if err := postgres.db.QueryRowContext(ctx, `SELECT value FROM assets WHERE scan_id=$1`, scanID).Scan(&storedValue); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(storedValue, encryptedFieldPrefix) || strings.Contains(storedValue, asset.Value) {
		t.Fatalf("asset was not encrypted at rest: %q", storedValue)
	}
	assets, err := postgres.Assets(ctx, scanID)
	if err != nil || len(assets) != 1 || assets[0].Value != asset.Value || assets[0].Metadata != asset.Metadata {
		t.Fatalf("encrypted asset read round trip: assets=%#v err=%v", assets, err)
	}
}
