package modules

import (
	"context"
	"errors"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

var ErrRawTCPUnavailable = errors.New("raw TCP scanning is disabled: this build only supports verified TCP connect scanning")

type ScanTechnique string

const (
	ScanSYN        ScanTechnique = "SYN"
	ScanACK        ScanTechnique = "ACK"
	ScanFIN        ScanTechnique = "FIN"
	ScanNULL       ScanTechnique = "NULL"
	ScanXMAS       ScanTechnique = "XMAS"
	ScanIdle       ScanTechnique = "IDLE"
	ScanFragmented ScanTechnique = "FRAGMENTED"
	ScanDecoy      ScanTechnique = "DECOY"
)

type RawTCPScanner struct {
	db        *store.SQLiteCLI
	guard     scope.Guard
	technique ScanTechnique
}

func NewRawTCPScanner(db *store.SQLiteCLI, guard scope.Guard, tech ScanTechnique) *RawTCPScanner {
	if tech == "" {
		tech = ScanSYN
	}
	return &RawTCPScanner{
		db:        db,
		guard:     guard,
		technique: tech,
	}
}

func (m *RawTCPScanner) Name() string {
	return "raw_tcp_scanner"
}

func (m *RawTCPScanner) Subscriptions() []string {
	return []string{"host.discovered"}
}

func (m *RawTCPScanner) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	return nil, ErrRawTCPUnavailable
}
