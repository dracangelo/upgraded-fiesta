package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"
)

type FeedMetadata struct {
	Source     string
	Version    string
	Provenance string
	FetchedAt  time.Time
}

type VulnerabilityRecord struct {
	CVE, CWE, Description, CPEConfigurations string
	CVSS, EPSS                               float64
	KEV                                      bool
}

func (s *SQLiteCLI) VulnerabilitiesForCPE(ctx context.Context, cpe string) ([]VulnerabilityRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT cve_id,cwe_id,cvss,epss,kev,description,cpe_configurations FROM nvd_cves WHERE cpe_configurations LIKE ?`, "%target="+cpe+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []VulnerabilityRecord
	for rows.Next() {
		var record VulnerabilityRecord
		var kev int
		if err := rows.Scan(&record.CVE, &record.CWE, &record.CVSS, &record.EPSS, &kev, &record.Description, &record.CPEConfigurations); err != nil {
			return nil, err
		}
		record.KEV = kev != 0
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *SQLiteCLI) RecordFeed(ctx context.Context, metadata FeedMetadata, raw []byte) error {
	if metadata.FetchedAt.IsZero() {
		metadata.FetchedAt = time.Now().UTC()
	}
	if metadata.Version == "" {
		metadata.Version = metadata.FetchedAt.Format(time.RFC3339)
	}
	sum := sha256.Sum256(raw)
	_, err := s.db.ExecContext(ctx, `INSERT INTO intelligence_feeds(source,version,provenance,checksum,fetched_at) VALUES(?,?,?,?,?)
ON CONFLICT(source) DO UPDATE SET version=excluded.version,provenance=excluded.provenance,checksum=excluded.checksum,fetched_at=excluded.fetched_at,updated_at=CURRENT_TIMESTAMP`, metadata.Source, metadata.Version, metadata.Provenance, fmt.Sprintf("%x", sum[:]), metadata.FetchedAt.UTC().Format(time.RFC3339))
	return err
}

func (s *SQLiteCLI) AddSuppression(ctx context.Context, fingerprint, reason string, expiresAt time.Time) error {
	expires := ""
	if !expiresAt.IsZero() {
		expires = expiresAt.UTC().Format(time.RFC3339)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO finding_suppressions(fingerprint,reason,expires_at) VALUES(?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET reason=excluded.reason,expires_at=excluded.expires_at`, fingerprint, reason, expires)
	return err
}

func (s *SQLiteCLI) IsSuppressed(ctx context.Context, fingerprint string) (bool, error) {
	var expires string
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(expires_at,'') FROM finding_suppressions WHERE fingerprint=?`, fingerprint).Scan(&expires)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	if expires == "" {
		return true, nil
	}
	expiry, err := time.Parse(time.RFC3339, expires)
	if err != nil {
		return false, err
	}
	return expiry.After(time.Now().UTC()), nil
}

func (s *SQLiteCLI) RetainEvidence(ctx context.Context, scanID, findingFingerprint, classification string, evidence []byte, retainedUntil time.Time) error {
	sum := sha256.Sum256(evidence)
	until := ""
	if !retainedUntil.IsZero() {
		until = retainedUntil.UTC().Format(time.RFC3339)
	}
	_, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO evidence_records(scan_id,finding_fingerprint,sha256,classification,retained_until) VALUES(?,?,?,?,?)`, scanID, findingFingerprint, fmt.Sprintf("%x", sum[:]), classification, until)
	return err
}
