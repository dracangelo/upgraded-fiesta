package store

import (
	"context"
	"fmt"

	"enumscan/internal/models"
)

// AddPortObservation records factual scan-time state separately from derived
// assets, allowing operators to review port history without inferring it from
// a missing asset in a later scan.
func (s *SQLiteCLI) AddPortObservation(ctx context.Context, observation models.PortObservation) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("database connection is nil")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO port_observations(scan_id,host,port,protocol,state,latency_ms,evidence) VALUES(?,?,?,?,?,?,?)`, observation.ScanID, observation.Host, observation.Port, observation.Protocol, observation.State, observation.LatencyMS, observation.Evidence)
	return err
}
