package models

import "time"

type Config struct {
	Database     DatabaseConfig
	Scope        ScopeConfig
	Scheduler    SchedulerConfig
	Discovery    DiscoveryConfig
	PortScan     PortScanConfig
	HTTP         HTTPConfig
	Specialized  SpecializedConfig
	PassiveIntel PassiveIntelConfig
	Scan         ScanConfig
	Reporting    ReportingConfig
}

type DatabaseConfig struct {
	Path string
}

type ScopeConfig struct {
	AllowedTargets []string
	// Authorization is an operator-supplied reference to the written approval
	// for the targets in this configuration (for example, a ticket number).
	Authorization string
}

type SchedulerConfig struct {
	Concurrency          int
	GlobalRateLimitMS    int
	PerTargetRateLimitMS int
	ModuleTimeoutMS      int
}

type DiscoveryConfig struct {
	CIDRMaxHosts                 int
	EnableReverseDNS             bool
	EnableWildcardDNS            bool
	EnableRDAP                   bool
	PassiveDNSFiles              []string
	CertificateTransparencyFiles []string
}

type PortScanConfig struct {
	Profile       string
	TCPPorts      []int
	UDPPorts      []int
	EnableTCP     bool
	EnableUDP     bool
	EnableBanner  bool
	EnableRawSYN  bool
	BaseTimeoutMS int
	MaxTimeoutMS  int
}

type HTTPConfig struct {
	MaxDepth           int
	MaxPagesPerHost    int
	EnableTLS          bool
	EnableCrawler      bool
	EnableJSAnalysis   bool
	EnableAPIDiscovery bool
	EnableScreenshots  bool
	APIPaths           []string
	EnableDirectoryAPI bool
	DirectoryWordlist  []string
	MaxDirectoryPaths  int
	EnableSecretIntel  bool
}

type SpecializedConfig struct {
	EnableSMB       bool
	EnableLDAP      bool
	EnableSNMP      bool
	EnableCloud     bool
	EnableContainer bool
	EnableDatabase  bool
	SNMPCommunities []string
}

// PassiveIntelConfig controls optional third-party lookups. Credentials are
// read from environment variables rather than persisted in scan configuration.
type PassiveIntelConfig struct {
	Enabled bool
	Sources []string
}

type ScanConfig struct {
	Profile string
	Targets []string
	Ports   []int
}

type ReportingConfig struct {
	OutputDir string
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
