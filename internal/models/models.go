package models

import "time"

type Config struct {
	Database      DatabaseConfig
	Scope         ScopeConfig
	Scheduler     SchedulerConfig
	Discovery     DiscoveryConfig
	PortScan      PortScanConfig
	HTTP          HTTPConfig
	Specialized   SpecializedConfig
	PassiveIntel  PassiveIntelConfig
	Neo4j         Neo4jConfig
	Scan          ScanConfig
	Reporting     ReportingConfig
	Notifications NotificationConfig
	Monitoring    MonitoringConfig
	API           APIConfig
	Secrets       SecretsConfig
	ActiveTesting ActiveTestingConfig
}

// ActiveTestingConfig is a separate authorization boundary for intrusive
// checks. A normal scan authorization never implicitly enables these probes.
type ActiveTestingConfig struct {
	Enabled               bool
	AuthorizationExpires  string
	Operator              string
	AcknowledgementEnv    string
	AllowedTechniques     []string
	MaxRequestsPerHost    int
	MaxConcurrency        int
	MinimumRequestDelayMS int
}

type DatabaseConfig struct {
	Path                 string
	Driver               string
	EncryptionKeyEnv     string
	EncryptionKeySecret  string
	PostgresDSNEnv       string
	PostgresMaxOpenConns int
	PostgresMaxIdleConns int
}

type SecretsConfig struct {
	Provider  string
	Endpoint  string
	TokenEnv  string
	TokenFile string
	Namespace string
	Project   string
	Region    string
	Mount     string
	Service   string
}

type Neo4jConfig struct {
	URI         string
	Username    string
	PasswordEnv string
}

type ScopeConfig struct {
	AllowedTargets []string
	// Authorization is an operator-supplied reference to the written approval
	// for the targets in this configuration (for example, a ticket number).
	Authorization string
}

type SchedulerConfig struct {
	Concurrency           int
	EnableAdaptiveWorkers bool
	MinConcurrency        int
	GlobalRateLimitMS     int
	PerTargetRateLimitMS  int
	ModuleTimeoutMS       int
}

type DiscoveryConfig struct {
	CIDRMaxHosts                 int
	EnableDNSDiscovery           bool
	EnableDNSRecords             bool
	EnableReverseDNS             bool
	EnableWildcardDNS            bool
	EnableRDAP                   bool
	EnableICMPSweep              bool
	EnableTCPHostProbes          bool
	TCPProbePorts                []int
	EnableUDPLiveProbes          bool
	UDPProbePorts                []int
	EnableTCPSYNProbes           bool
	EnableTCPACKProbes           bool
	EnableSNMPProbes             bool
	SNMPCommunities              []string
	SNMPProbePorts               []int
	EnableLiveCapture            bool
	CaptureInterface             string
	CaptureDurationMS            int
	PassiveDNSFiles              []string
	CertificateTransparencyFiles []string
	PassiveCaptureFiles          []string
	HistoricalURLFiles           []string
}

type PortScanConfig struct {
	Profile             string
	TCPPorts            []int
	UDPPorts            []int
	EnableTCP           bool
	EnableUDP           bool
	EnableBanner        bool
	EnableRawSYN        bool
	EnableRawScanning   bool
	RawTechniques       []string
	DecoyIPs            []string
	ZombieHost          string
	EnableTwoPhaseSweep bool
	MaxConcurrentPorts  int
	RecordClosedPorts   bool
	BaseTimeoutMS       int
	MaxTimeoutMS        int
}

type HTTPConfig struct {
	MaxDepth                    int
	MaxPagesPerHost             int
	EnableTLS                   bool
	EnableCrawler               bool
	EnableJSAnalysis            bool
	EnableAPIDiscovery          bool
	EnableScreenshots           bool
	ScreenshotRenderer          string
	ScreenshotRendererArgs      []string
	ScreenshotOutputDir         string
	MaxScreenshotsPerScan       int
	APIPaths                    []string
	EnableDirectoryAPI          bool
	DirectoryWordlist           []string
	MaxDirectoryPaths           int
	EnableSecretIntel           bool
	EnableWebManifest           bool
	EnableRedirectTracking      bool
	EnableMethodEnumeration     bool
	EnableSourceMapAnalysis     bool
	WappalyzerRuleFiles         []string
	EnableCookieJar             bool
	EnableAuthenticatedCrawling bool
	AuthCookieEnv               string
	EnableHTTP3                 bool
	EnableGRPCReflection        bool
	GRPCReflectionPorts         []int
}

type SpecializedConfig struct {
	EnableSMB                 bool
	EnableLDAP                bool
	EnableSNMP                bool
	EnableCloud               bool
	EnableContainer           bool
	EnableDatabase            bool
	EnableProtocolEnumeration bool
	SNMPCommunities           []string
}

// PassiveIntelConfig controls optional third-party lookups. Credentials are
// read from environment variables rather than persisted in scan configuration.
type PassiveIntelConfig struct {
	Enabled               bool
	Sources               []string
	ProviderControls      []string
	ProviderVersions      []string
	EnableQuotaDiscovery  bool
	EnableUpdateChecks    bool
	ProviderMinIntervalMS int
	MaxRetryAfterMS       int
}

type ScanConfig struct {
	Profile       string
	CustomProfile string
	Targets       []string
	Ports         []int
	// ModulePlan is derived from the selected profile when configuration is
	// loaded. It is intentionally not a user-facing YAML option: operators
	// select a profile or custom profile instead of maintaining module names.
	ModulePlan     []string
	ProfileApplied bool
}

type ReportingConfig struct {
	OutputDir         string
	LocalLLMURL       string
	LocalLLMModel     string
	LocalLLMTimeoutMS int
}

// NotificationConfig is an optional outbound subscription. It is disabled by
// default and only handles a completed scan event; credentials are not stored.
type NotificationConfig struct {
	EnableScanCompletedWebhook bool
	WebhookURL                 string
}

// MonitoringConfig enables a bounded recurring run only when an operator
// explicitly invokes the monitor command. It never broadens scan scope.
type MonitoringConfig struct {
	Enabled         bool
	IntervalMinutes int
	MaxRuns         int
}

// APIConfig keeps dashboard/API credentials out of YAML. When enabled, the
// token environment variable contains comma-separated token:role pairs.
type APIConfig struct {
	RequireAuth bool
	TokensEnv   string
}

// ScanRun is the compact, non-sensitive history record used by the operator
// console. Counts are computed at read time so they always reflect persisted
// evidence, including an in-progress scan.
type ScanRun struct {
	ScanID       string     `json:"scan_id"`
	Status       string     `json:"status"`
	Error        string     `json:"error,omitempty"`
	StartedAt    time.Time  `json:"started_at"`
	FinishedAt   *time.Time `json:"finished_at,omitempty"`
	AssetCount   int        `json:"asset_count"`
	FindingCount int        `json:"finding_count"`
	EventCount   int        `json:"event_count"`
}

type Asset struct {
	ID        int64     `json:"id"`
	ScanID    string    `json:"scan_id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Parent    string    `json:"parent"`
	Metadata  string    `json:"metadata"`
	CreatedAt time.Time `json:"created_at"`
}

type Finding struct {
	ID           int64     `json:"id"`
	ScanID       string    `json:"scan_id"`
	Severity     string    `json:"severity"`
	Confidence   string    `json:"confidence"`
	Verification string    `json:"verification,omitempty"`
	Asset        string    `json:"asset"`
	Title        string    `json:"title"`
	Evidence     string    `json:"evidence"`
	Remediation  string    `json:"remediation"`
	CWE          string    `json:"cwe,omitempty"`
	CVE          string    `json:"cve,omitempty"`
	CVSS         float64   `json:"cvss,omitempty"`
	EPSS         float64   `json:"epss,omitempty"`
	KEV          bool      `json:"kev,omitempty"`
	References   []string  `json:"references,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type Event struct {
	ID     int64             `json:"id"`
	ScanID string            `json:"scan_id"`
	Type   string            `json:"type"`
	Target string            `json:"target"`
	Data   map[string]string `json:"data"`
}

type Checkpoint struct {
	ScanID    string
	Module    string
	EventType string
	Target    string
	Status    string
	Error     string
}

// DistributedScanJob is a durable, coordinator-owned lease record. It holds no
// target or credential data; agents must obtain the authorized configuration by
// a future mutually authenticated transport.
type DistributedScanJob struct {
	ID               string    `json:"id"`
	ScanID           string    `json:"scan_id"`
	AuthorizationRef string    `json:"authorization_ref"`
	ConfigDigest     string    `json:"config_digest"`
	Status           string    `json:"status"`
	LeaseOwner       string    `json:"lease_owner,omitempty"`
	LeaseUntil       time.Time `json:"lease_until,omitempty"`
	Attempts         int       `json:"attempts"`
	CreatedAt        time.Time `json:"created_at"`
}

// DistributedAgent is the coordinator's durable enrollment record. Public keys
// are retained only as SHA-256 fingerprints until mutually authenticated agent
// transport is implemented.
type DistributedAgent struct {
	ID                   string    `json:"id"`
	PublicKeyFingerprint string    `json:"public_key_fingerprint"`
	Status               string    `json:"status"`
	LastHeartbeat        time.Time `json:"last_heartbeat"`
	RegisteredAt         time.Time `json:"registered_at"`
}

// DistributedCoordinatorStatus is a local operator view of the durable
// coordinator ledger. It intentionally contains no target configuration,
// credentials, or remote-agent transport details.
type DistributedCoordinatorStatus struct {
	Jobs         []DistributedScanJob `json:"jobs"`
	Agents       []DistributedAgent   `json:"agents"`
	JobsByStatus map[string]int       `json:"jobs_by_status"`
}

// DistributedEvidence is the bounded result envelope returned by a lease-owning
// agent. Every record is scan-bound again by the coordinator before insertion.
type DistributedEvidence struct {
	JobID    string    `json:"job_id"`
	Assets   []Asset   `json:"assets,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
	Events   []Event   `json:"events,omitempty"`
}

type APIAuditEntry struct {
	ID        int64     `json:"id"`
	Actor     string    `json:"actor"`
	Role      string    `json:"role"`
	Action    string    `json:"action"`
	ScanID    string    `json:"scan_id,omitempty"`
	Status    int       `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// ModuleRun is an auditable, structured outcome for one module invocation.
// It deliberately records an error separately from scan findings so transport,
// parsing, and storage failures cannot be mistaken for an empty result.
type ModuleRun struct {
	ScanID    string        `json:"scan_id"`
	Module    string        `json:"module"`
	EventType string        `json:"event_type"`
	Target    string        `json:"target"`
	Status    string        `json:"status"`
	Duration  time.Duration `json:"duration"`
	Error     string        `json:"error,omitempty"`
}

// ModuleRunLog is a persisted, structured activity record derived from an
// actual module invocation. It contains no simulated progress messages.
type ModuleRunLog struct {
	ID         int64     `json:"id"`
	ScanID     string    `json:"scan_id"`
	Module     string    `json:"module"`
	EventType  string    `json:"event_type"`
	Target     string    `json:"target"`
	Status     string    `json:"status"`
	DurationMS int64     `json:"duration_ms"`
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// ScanRuntimeStats is a best-effort snapshot written by the active local
// scheduler. It is intentionally not an ETA: only observable worker and
// queue state is included.
type ScanRuntimeStats struct {
	ScanID          string    `json:"scan_id"`
	WorkerCapacity  int       `json:"worker_capacity"`
	ActiveWorkers   int       `json:"active_workers"`
	RunningModules  int       `json:"running_modules"`
	QueueHigh       int       `json:"queue_high"`
	QueueNormal     int       `json:"queue_normal"`
	QueueLow        int       `json:"queue_low"`
	EnqueuedEvents  int64     `json:"enqueued_events"`
	CompletedEvents int64     `json:"completed_events"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type ScanHealth struct {
	ScanID        string `json:"scan_id"`
	Status        string `json:"status"`
	CompletedRuns int    `json:"completed_runs"`
	FailedRuns    int    `json:"failed_runs"`
	Healthy       bool   `json:"healthy"`
}

type SavedQuery struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Query     string    `json:"query"`
	CreatedAt time.Time `json:"created_at"`
}

type PortObservation struct {
	ScanID     string    `json:"scan_id"`
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol"`
	State      string    `json:"state"`
	LatencyMS  int64     `json:"latency_ms"`
	Evidence   string    `json:"evidence,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
}
