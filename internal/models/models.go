package models

import "time"

type Config struct {
	Database  DatabaseConfig
	Scope     ScopeConfig
	Scheduler SchedulerConfig
	Scan      ScanConfig
	Reporting ReportingConfig
}

type DatabaseConfig struct {
	Path string
}

type ScopeConfig struct {
	AllowedTargets []string
}

type SchedulerConfig struct {
	Concurrency          int
	GlobalRateLimitMS    int
	PerTargetRateLimitMS int
	ModuleTimeoutMS      int
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
	ID          int64     `json:"id"`
	ScanID      string    `json:"scan_id"`
	Severity    string    `json:"severity"`
	Confidence  string    `json:"confidence"`
	Asset       string    `json:"asset"`
	Title       string    `json:"title"`
	Evidence    string    `json:"evidence"`
	Remediation string    `json:"remediation"`
	CreatedAt   time.Time `json:"created_at"`
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
