package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"
)

// VulnerabilitiesForCPE returns the locally ingested intelligence records; it
// never performs a network lookup while serving a scan.
func (p *PostgresStore) VulnerabilitiesForCPE(ctx context.Context, cpe string) ([]VulnerabilityRecord, error) {
	if p.db == nil {
		return nil, p.notOpenError()
	}
	rows, err := p.db.QueryContext(ctx, `SELECT cve_id,cwe_id,cvss,epss,kev,description,cpe_configurations FROM nvd_cves WHERE cpe_configurations LIKE $1`, "%target="+cpe+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := make([]VulnerabilityRecord, 0)
	for rows.Next() {
		var record VulnerabilityRecord
		if err := rows.Scan(&record.CVE, &record.CWE, &record.CVSS, &record.EPSS, &record.KEV, &record.Description, &record.CPEConfigurations); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (p *PostgresStore) RecordFeed(ctx context.Context, metadata FeedMetadata, raw []byte) error {
	if p.db == nil {
		return p.notOpenError()
	}
	if metadata.FetchedAt.IsZero() {
		metadata.FetchedAt = time.Now().UTC()
	}
	if metadata.Version == "" {
		metadata.Version = metadata.FetchedAt.Format(time.RFC3339)
	}
	sum := sha256.Sum256(raw)
	_, err := p.db.ExecContext(ctx, `INSERT INTO intelligence_feeds(source,version,provenance,checksum,fetched_at) VALUES($1,$2,$3,$4,$5)
ON CONFLICT(source) DO UPDATE SET version=EXCLUDED.version,provenance=EXCLUDED.provenance,checksum=EXCLUDED.checksum,fetched_at=EXCLUDED.fetched_at,updated_at=CURRENT_TIMESTAMP`, metadata.Source, metadata.Version, metadata.Provenance, fmt.Sprintf("%x", sum[:]), metadata.FetchedAt.UTC())
	return err
}

func (p *PostgresStore) AddSuppression(ctx context.Context, fingerprint, reason string, expiresAt time.Time) error {
	if p.db == nil {
		return p.notOpenError()
	}
	var expiry any
	if expiresAt.IsZero() {
		expiry = nil
	} else {
		expiry = expiresAt.UTC()
	}
	_, err := p.db.ExecContext(ctx, `INSERT INTO finding_suppressions(fingerprint,reason,expires_at) VALUES($1,$2,$3) ON CONFLICT(fingerprint) DO UPDATE SET reason=EXCLUDED.reason,expires_at=EXCLUDED.expires_at`, fingerprint, reason, expiry)
	return err
}

func (p *PostgresStore) IsSuppressed(ctx context.Context, fingerprint string) (bool, error) {
	if p.db == nil {
		return false, p.notOpenError()
	}
	var expiry sql.NullTime
	err := p.db.QueryRowContext(ctx, `SELECT expires_at FROM finding_suppressions WHERE fingerprint=$1`, fingerprint).Scan(&expiry)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !expiry.Valid || expiry.Time.After(time.Now().UTC()), nil
}

func (p *PostgresStore) RetainEvidence(ctx context.Context, scanID, findingFingerprint, classification string, evidence []byte, retainedUntil time.Time) error {
	if p.db == nil {
		return p.notOpenError()
	}
	sum := sha256.Sum256(evidence)
	var until any
	if retainedUntil.IsZero() {
		until = nil
	} else {
		until = retainedUntil.UTC()
	}
	_, err := p.db.ExecContext(ctx, `INSERT INTO evidence_records(scan_id,finding_fingerprint,sha256,classification,retained_until) VALUES($1,$2,$3,$4,$5) ON CONFLICT(scan_id,finding_fingerprint,sha256) DO NOTHING`, scanID, findingFingerprint, fmt.Sprintf("%x", sum[:]), classification, until)
	return err
}

// CachedValue is a bounded, non-sensitive operator cache. It must not be
// used for scan responses or credentials.
func (p *PostgresStore) CachedValue(ctx context.Context, key string) (string, bool, error) {
	if p.db == nil {
		return "", false, p.notOpenError()
	}
	var value string
	var expires time.Time
	err := p.db.QueryRowContext(ctx, `SELECT value,expires_at FROM operator_cache WHERE cache_key=$1`, key).Scan(&value, &expires)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !expires.After(time.Now().UTC()) {
		_, _ = p.db.ExecContext(ctx, `DELETE FROM operator_cache WHERE cache_key=$1`, key)
		return "", false, nil
	}
	return value, true, nil
}

func (p *PostgresStore) PutCachedValue(ctx context.Context, key, value string, ttl time.Duration) error {
	if p.db == nil {
		return p.notOpenError()
	}
	const maxCacheEntries = 512
	const maxCacheValueBytes = 1 << 20
	if key == "" || len(value) > maxCacheValueBytes {
		return fmt.Errorf("invalid operator cache value")
	}
	if ttl <= 0 {
		return fmt.Errorf("operator cache TTL must be positive")
	}
	now := time.Now().UTC()
	if _, err := p.db.ExecContext(ctx, `DELETE FROM operator_cache WHERE expires_at <= $1`, now); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, `INSERT INTO operator_cache(cache_key,value,expires_at,updated_at) VALUES($1,$2,$3,CURRENT_TIMESTAMP)
ON CONFLICT(cache_key) DO UPDATE SET value=EXCLUDED.value,expires_at=EXCLUDED.expires_at,updated_at=CURRENT_TIMESTAMP`, key, value, now.Add(ttl)); err != nil {
		return err
	}
	_, err := p.db.ExecContext(ctx, `DELETE FROM operator_cache WHERE cache_key IN (
SELECT cache_key FROM operator_cache ORDER BY updated_at DESC,cache_key DESC OFFSET $1
)`, maxCacheEntries)
	return err
}
