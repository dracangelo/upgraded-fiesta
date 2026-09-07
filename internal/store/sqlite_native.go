package store

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	"enumscan/internal/models"
)

type NativeSQLiteStore struct {
	mu     sync.Mutex
	dbPath string
	db     *sql.DB
}

func NewNativeSQLiteStore(dbPath string) *NativeSQLiteStore {
	return &NativeSQLiteStore{
		dbPath: dbPath,
	}
}

func (n *NativeSQLiteStore) Open() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.db != nil {
		return nil
	}

	// Dynamic fallback abstraction for standard database/sql driver.
	for _, driver := range []string{"sqlite3", "sqlite"} {
		db, err := sql.Open(driver, n.dbPath)
		if err == nil && db.Ping() == nil {
			n.db = db
			return nil
		}
	}
	return fmt.Errorf("no supported SQLite driver is available; use OpenSQLiteCLI")
}

func (n *NativeSQLiteStore) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.db != nil {
		err := n.db.Close()
		n.db = nil
		return err
	}
	return nil
}

func (n *NativeSQLiteStore) Migrate(ctx context.Context) error {
	return fmt.Errorf("NativeSQLiteStore is deprecated and has no migration contract; use OpenSQLiteCLI")
}

func (n *NativeSQLiteStore) AddAsset(ctx context.Context, asset models.Asset) error {
	if n.db == nil {
		return fmt.Errorf("native SQLite store is not open")
	}
	_, err := n.db.ExecContext(ctx, "INSERT INTO assets(scan_id,type,value,parent,metadata) VALUES(?,?,?,?,?)",
		asset.ScanID, asset.Type, asset.Value, asset.Parent, asset.Metadata)
	return err
}

func (n *NativeSQLiteStore) AddFinding(ctx context.Context, finding models.Finding) error {
	if n.db == nil {
		return fmt.Errorf("native SQLite store is not open")
	}
	_, err := n.db.ExecContext(ctx, "INSERT INTO findings(scan_id,severity,confidence,asset,title,evidence,remediation,cwe,cve,cvss,epss,kev) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
		finding.ScanID, finding.Severity, finding.Confidence, finding.Asset, finding.Title, finding.Evidence, finding.Remediation, finding.CWE, finding.CVE, finding.CVSS, finding.EPSS, finding.KEV)
	return err
}
