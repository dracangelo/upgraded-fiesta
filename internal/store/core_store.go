package store

import (
	"context"
	"time"

	"enumscan/internal/models"
)

// CoreEvidenceStore is the deliberately small, backend-neutral persistence
// contract used by the scan lifecycle and operator history. Keeping this
// contract explicit prevents PostgreSQL support from being inferred from a
// partial set of similarly named methods while the remaining SQLite-specific
// module APIs are migrated in later increments.
type CoreEvidenceStore interface {
	Close() error
	Migrate(context.Context) error
	StartScan(context.Context, string) error
	FinishScan(context.Context, string, string, string) error
	UpdateScanStatus(context.Context, string, string) error
	GetScanStatus(context.Context, string) (string, error)
	ScanRuns(context.Context, int) ([]models.ScanRun, error)
	AddAsset(context.Context, models.Asset) error
	Assets(context.Context, string) ([]models.Asset, error)
	AddFinding(context.Context, models.Finding) error
	Findings(context.Context, string) ([]models.Finding, error)
	AddEvent(context.Context, models.Event) (int64, error)
	Events(context.Context, string) ([]models.Event, error)
	CheckpointStatus(context.Context, string, string, string, string) (string, error)
	UpsertCheckpoint(context.Context, models.Checkpoint) error
}

// RuntimeStore is the backend-neutral contract used by normal scan execution,
// the operator API, and reporting. SQLite-specific file backup and live
// evidence encryption intentionally do not belong here: PostgreSQL has no
// safe equivalent to copying or replacing its server-side database file.
type RuntimeStore interface {
	CoreEvidenceStore
	AssetByID(context.Context, int64) (models.Asset, error)
	Exec(context.Context, string) error
	DeleteAssets(context.Context, []int64) error
	DeleteFindings(context.Context, []int64) error
	CachedValue(context.Context, string) (string, bool, error)
	PutCachedValue(context.Context, string, string, time.Duration) error
	VulnerabilitiesForCPE(context.Context, string) ([]VulnerabilityRecord, error)
	RecordFeed(context.Context, FeedMetadata, []byte) error
	AddSuppression(context.Context, string, string, time.Time) error
	IsSuppressed(context.Context, string) (bool, error)
	RetainEvidence(context.Context, string, string, string, []byte, time.Time) error
	RecordModuleRun(context.Context, models.ModuleRun) error
	ScanHealth(context.Context, string) (models.ScanHealth, error)
	AddPortObservation(context.Context, models.PortObservation) error
	UpsertRuntimeStats(context.Context, models.ScanRuntimeStats) error
	ScanRuntimeStats(context.Context, string) (models.ScanRuntimeStats, error)
	RecentModuleRunLogs(context.Context, string, int) ([]models.ModuleRunLog, error)
	ScanMetrics(context.Context, string) (ScanMetrics, error)
	SaveQuery(context.Context, string, string) error
	SavedQueries(context.Context) ([]models.SavedQuery, error)
	Search(context.Context, string, string) ([]models.Asset, []models.Finding, error)
	SearchCategorized(context.Context, string, string, string) (CategorizedSearchResult, error)
	ScreenshotAssets(context.Context, string) ([]models.Asset, error)
	RecordAPIAudit(context.Context, models.APIAuditEntry) error
	RecentAPIAudit(context.Context, int) ([]models.APIAuditEntry, error)
	RegisterDistributedAgent(context.Context, string, string) (models.DistributedAgent, error)
	AuthenticateDistributedAgent(context.Context, string, string, string, string, []byte) error
	HeartbeatDistributedAgent(context.Context, string) error
	EnqueueDistributedScanJob(context.Context, string, string, string) (models.DistributedScanJob, error)
	LeaseDistributedScanJob(context.Context, string, time.Duration) (models.DistributedScanJob, error)
	IngestDistributedEvidence(context.Context, string, models.DistributedEvidence) error
	CompleteDistributedScanJob(context.Context, string, string, string) error
	DistributedCoordinatorStatus(context.Context, int) (models.DistributedCoordinatorStatus, error)
	Ping(context.Context) error
}

var (
	_ CoreEvidenceStore = (*SQLiteCLI)(nil)
	_ CoreEvidenceStore = (*PostgresStore)(nil)
	_ RuntimeStore      = (*SQLiteCLI)(nil)
	_ RuntimeStore      = (*PostgresStore)(nil)
)
