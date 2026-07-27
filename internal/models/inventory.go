package models

import "time"

type InventoryAsset struct {
	ID        int64     `json:"id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	Parent    string    `json:"parent,omitempty"`
	Owner     string    `json:"owner,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	ScanCount int       `json:"scan_count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type ServiceRecord struct {
	ID        int64     `json:"id"`
	Asset     string    `json:"asset"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
	Service   string    `json:"service"`
	Banner    string    `json:"banner,omitempty"`
	CPE       string    `json:"cpe,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type TechnologyRecord struct {
	ID         int64     `json:"id"`
	Asset      string    `json:"asset"`
	Product    string    `json:"product"`
	Category   string    `json:"category"`
	Version    string    `json:"version,omitempty"`
	Confidence string    `json:"confidence"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

type CertificateRecord struct {
	ID          int64     `json:"id"`
	Asset       string    `json:"asset"`
	Fingerprint string    `json:"fingerprint"`
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	ExpiryDate  time.Time `json:"expiry_date"`
	FirstSeen   time.Time `json:"first_seen"`
}

type SecretRecord struct {
	ID        int64     `json:"id"`
	Asset     string    `json:"asset"`
	Type      string    `json:"type"`
	Snippet   string    `json:"snippet"`
	Entropy   float64   `json:"entropy"`
	FirstSeen time.Time `json:"first_seen"`
}

type ScreenshotRecord struct {
	ID         int64     `json:"id"`
	Asset      string    `json:"asset"`
	FilePath   string    `json:"file_path"`
	Resolution string    `json:"resolution"`
	Hash       string    `json:"hash"`
	CreatedAt  time.Time `json:"created_at"`
}

type GraphNode struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Type  string `json:"type"`
}

type GraphEdge struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Relation string `json:"relation"`
}

type AssetGraph struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

type PortHistoryRecord struct {
	ID        int64     `json:"id"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	State     string    `json:"state"` // "open", "closed", "filtered"
	Timestamp time.Time `json:"timestamp"`
}
