package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"enumscan/internal/models"
)

const datastoreEncryptionVerifier = "enumscan-live-datastore-key-v1"

func (s *SQLiteCLI) seal(domain, value string) (string, error) {
	if s.encryptor == nil {
		return value, nil
	}
	return s.encryptor.SealString(domain, value)
}

func (s *SQLiteCLI) open(domain, value string) (string, error) {
	if s.encryptor == nil {
		if strings.HasPrefix(value, encryptedFieldPrefix) {
			return "", fmt.Errorf("datastore contains encrypted evidence but no key was configured")
		}
		return value, nil
	}
	return s.encryptor.OpenString(domain, value)
}

func (s *SQLiteCLI) protectAsset(asset models.Asset) (models.Asset, error) {
	var err error
	if asset.Value, err = s.seal("assets.value", asset.Value); err != nil {
		return asset, err
	}
	if asset.Parent, err = s.seal("assets.parent", asset.Parent); err != nil {
		return asset, err
	}
	if asset.Metadata, err = s.seal("assets.metadata", asset.Metadata); err != nil {
		return asset, err
	}
	return asset, nil
}

func (s *SQLiteCLI) revealAsset(asset *models.Asset) error {
	var err error
	if asset.Value, err = s.open("assets.value", asset.Value); err != nil {
		return err
	}
	if asset.Parent, err = s.open("assets.parent", asset.Parent); err != nil {
		return err
	}
	if asset.Metadata, err = s.open("assets.metadata", asset.Metadata); err != nil {
		return err
	}
	return nil
}

func (s *SQLiteCLI) protectFinding(finding models.Finding) (models.Finding, error) {
	fields := []struct {
		domain string
		value  *string
	}{
		{"findings.asset", &finding.Asset}, {"findings.title", &finding.Title},
		{"findings.evidence", &finding.Evidence}, {"findings.remediation", &finding.Remediation},
	}
	for _, field := range fields {
		value, err := s.seal(field.domain, *field.value)
		if err != nil {
			return finding, err
		}
		*field.value = value
	}
	return finding, nil
}

func (s *SQLiteCLI) revealFinding(finding *models.Finding) error {
	fields := []struct {
		domain string
		value  *string
	}{
		{"findings.asset", &finding.Asset}, {"findings.title", &finding.Title},
		{"findings.evidence", &finding.Evidence}, {"findings.remediation", &finding.Remediation},
	}
	for _, field := range fields {
		value, err := s.open(field.domain, *field.value)
		if err != nil {
			return err
		}
		*field.value = value
	}
	return nil
}

func (s *SQLiteCLI) protectEvent(event models.Event) (models.Event, string, error) {
	target, err := s.seal("events.target", event.Target)
	if err != nil {
		return event, "", err
	}
	data, err := s.seal("events.data", flatten(event.Data))
	if err != nil {
		return event, "", err
	}
	event.Target = target
	return event, data, nil
}

func (s *SQLiteCLI) revealEvent(event *models.Event, data string) error {
	target, err := s.open("events.target", event.Target)
	if err != nil {
		return err
	}
	data, err = s.open("events.data", data)
	if err != nil {
		return err
	}
	event.Target, event.Data = target, inflate(data)
	return nil
}

func (s *SQLiteCLI) initializeEvidenceEncryption(ctx context.Context) error {
	var verifier string
	err := s.db.QueryRowContext(ctx, `SELECT verifier FROM datastore_encryption WHERE id=1`).Scan(&verifier)
	if err == nil {
		plaintext, err := s.encryptor.OpenString("datastore.verifier", verifier)
		if err != nil || plaintext != datastoreEncryptionVerifier {
			return fmt.Errorf("datastore encryption key verification failed")
		}
	} else if err == sql.ErrNoRows {
		verifier, err = s.encryptor.SealString("datastore.verifier", datastoreEncryptionVerifier)
		if err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO datastore_encryption(id,verifier) VALUES(1,?)`, verifier); err != nil {
			return err
		}
	} else {
		return err
	}
	return s.encryptExistingEvidence(ctx)
}

func (s *SQLiteCLI) encryptExistingEvidence(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT id,value,parent,metadata FROM assets`)
	if err != nil {
		return err
	}
	type assetRow struct {
		id                      int64
		value, parent, metadata string
	}
	var assets []assetRow
	for rows.Next() {
		var row assetRow
		if err := rows.Scan(&row.id, &row.value, &row.parent, &row.metadata); err != nil {
			rows.Close()
			return err
		}
		assets = append(assets, row)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, row := range assets {
		value, err := s.seal("assets.value", row.value)
		if err != nil {
			return err
		}
		parent, err := s.seal("assets.parent", row.parent)
		if err != nil {
			return err
		}
		metadata, err := s.seal("assets.metadata", row.metadata)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE assets SET value=?,parent=?,metadata=? WHERE id=?`, value, parent, metadata, row.id); err != nil {
			return err
		}
	}
	rows, err = tx.QueryContext(ctx, `SELECT id,asset,title,evidence,remediation FROM findings`)
	if err != nil {
		return err
	}
	type findingRow struct {
		id                                  int64
		asset, title, evidence, remediation string
	}
	var findings []findingRow
	for rows.Next() {
		var row findingRow
		if err := rows.Scan(&row.id, &row.asset, &row.title, &row.evidence, &row.remediation); err != nil {
			rows.Close()
			return err
		}
		findings = append(findings, row)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, row := range findings {
		asset, err := s.seal("findings.asset", row.asset)
		if err != nil {
			return err
		}
		title, err := s.seal("findings.title", row.title)
		if err != nil {
			return err
		}
		evidence, err := s.seal("findings.evidence", row.evidence)
		if err != nil {
			return err
		}
		remediation, err := s.seal("findings.remediation", row.remediation)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE findings SET asset=?,title=?,evidence=?,remediation=? WHERE id=?`, asset, title, evidence, remediation, row.id); err != nil {
			return err
		}
	}
	rows, err = tx.QueryContext(ctx, `SELECT id,target,data FROM events`)
	if err != nil {
		return err
	}
	type eventRow struct {
		id           int64
		target, data string
	}
	var events []eventRow
	for rows.Next() {
		var row eventRow
		if err := rows.Scan(&row.id, &row.target, &row.data); err != nil {
			rows.Close()
			return err
		}
		events = append(events, row)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, row := range events {
		target, err := s.seal("events.target", row.target)
		if err != nil {
			return err
		}
		data, err := s.seal("events.data", row.data)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE events SET target=?,data=? WHERE id=?`, target, data, row.id); err != nil {
			return err
		}
	}
	if err := s.encryptTableColumns(ctx, tx, "scan_runs", "scan_id", []string{"error"}, []string{"scan_runs.error"}); err != nil {
		return err
	}
	if err := s.encryptTableColumns(ctx, tx, "checkpoints", "rowid", []string{"target", "error"}, []string{"checkpoints.target", "checkpoints.error"}); err != nil {
		return err
	}
	if err := s.encryptTableColumns(ctx, tx, "module_runs", "id", []string{"target", "error"}, []string{"module_runs.target", "module_runs.error"}); err != nil {
		return err
	}
	if err := s.encryptTableColumns(ctx, tx, "port_observations", "id", []string{"host", "evidence"}, []string{"port_observations.host", "port_observations.evidence"}); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *SQLiteCLI) encryptTableColumns(ctx context.Context, tx *sql.Tx, table, keyColumn string, columns, domains []string) error {
	if len(columns) != len(domains) {
		return fmt.Errorf("invalid encryption column mapping")
	}
	rows, err := tx.QueryContext(ctx, fmt.Sprintf("SELECT %s,%s FROM %s", keyColumn, strings.Join(columns, ","), table))
	if err != nil {
		return err
	}
	type record struct {
		key    any
		values []string
	}
	var records []record
	for rows.Next() {
		record := record{values: make([]string, len(columns))}
		dest := make([]any, 1+len(columns))
		dest[0] = &record.key
		for index := range record.values {
			dest[index+1] = &record.values[index]
		}
		if err := rows.Scan(dest...); err != nil {
			rows.Close()
			return err
		}
		records = append(records, record)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	assignments := make([]string, len(columns))
	for index, column := range columns {
		assignments[index] = column + "=?"
	}
	query := fmt.Sprintf("UPDATE %s SET %s WHERE %s=?", table, strings.Join(assignments, ","), keyColumn)
	for _, record := range records {
		args := make([]any, 0, len(columns)+1)
		for index, value := range record.values {
			sealed, err := s.seal(domains[index], value)
			if err != nil {
				return err
			}
			args = append(args, sealed)
		}
		args = append(args, record.key)
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return err
		}
	}
	return nil
}
