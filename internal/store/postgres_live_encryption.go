package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"enumscan/internal/models"
)

func (p *PostgresStore) seal(domain, value string) (string, error) {
	if p.encryptor == nil {
		return value, nil
	}
	return p.encryptor.SealString(domain, value)
}

func (p *PostgresStore) open(domain, value string) (string, error) {
	if p.encryptor == nil {
		if strings.HasPrefix(value, encryptedFieldPrefix) {
			return "", fmt.Errorf("datastore contains encrypted evidence but no key was configured")
		}
		return value, nil
	}
	return p.encryptor.OpenString(domain, value)
}

func (p *PostgresStore) protectAsset(asset models.Asset) (models.Asset, error) {
	var err error
	if asset.Value, err = p.seal("assets.value", asset.Value); err != nil {
		return asset, err
	}
	if asset.Parent, err = p.seal("assets.parent", asset.Parent); err != nil {
		return asset, err
	}
	if asset.Metadata, err = p.seal("assets.metadata", asset.Metadata); err != nil {
		return asset, err
	}
	return asset, nil
}

func (p *PostgresStore) revealAsset(asset *models.Asset) error {
	var err error
	if asset.Value, err = p.open("assets.value", asset.Value); err != nil {
		return err
	}
	if asset.Parent, err = p.open("assets.parent", asset.Parent); err != nil {
		return err
	}
	if asset.Metadata, err = p.open("assets.metadata", asset.Metadata); err != nil {
		return err
	}
	return nil
}

func (p *PostgresStore) protectFinding(finding models.Finding) (models.Finding, error) {
	for _, field := range []struct {
		domain string
		value  *string
	}{{"findings.asset", &finding.Asset}, {"findings.title", &finding.Title}, {"findings.evidence", &finding.Evidence}, {"findings.remediation", &finding.Remediation}} {
		value, err := p.seal(field.domain, *field.value)
		if err != nil {
			return finding, err
		}
		*field.value = value
	}
	return finding, nil
}

func (p *PostgresStore) revealFinding(finding *models.Finding) error {
	for _, field := range []struct {
		domain string
		value  *string
	}{{"findings.asset", &finding.Asset}, {"findings.title", &finding.Title}, {"findings.evidence", &finding.Evidence}, {"findings.remediation", &finding.Remediation}} {
		value, err := p.open(field.domain, *field.value)
		if err != nil {
			return err
		}
		*field.value = value
	}
	return nil
}

func (p *PostgresStore) protectEvent(event models.Event) (models.Event, string, error) {
	target, err := p.seal("events.target", event.Target)
	if err != nil {
		return event, "", err
	}
	data, err := p.seal("events.data", flatten(event.Data))
	if err != nil {
		return event, "", err
	}
	event.Target = target
	return event, data, nil
}

func (p *PostgresStore) revealEvent(event *models.Event, data string) error {
	target, err := p.open("events.target", event.Target)
	if err != nil {
		return err
	}
	data, err = p.open("events.data", data)
	if err != nil {
		return err
	}
	event.Target, event.Data = target, inflate(data)
	return nil
}

func (p *PostgresStore) initializePostgresEvidenceEncryption(ctx context.Context) error {
	var verifier string
	err := p.db.QueryRowContext(ctx, `SELECT verifier FROM datastore_encryption WHERE id=1`).Scan(&verifier)
	if err == nil {
		plaintext, openErr := p.encryptor.OpenString("datastore.verifier", verifier)
		if openErr != nil || plaintext != datastoreEncryptionVerifier {
			return fmt.Errorf("datastore encryption key verification failed")
		}
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	verifier, err = p.encryptor.SealString("datastore.verifier", datastoreEncryptionVerifier)
	if err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx, `INSERT INTO datastore_encryption(id,verifier) VALUES(1,$1)`, verifier)
	return err
}
