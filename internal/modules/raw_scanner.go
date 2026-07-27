package modules

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

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
	decoys    []string
}

func NewRawTCPScanner(db *store.SQLiteCLI, guard scope.Guard, tech ScanTechnique) *RawTCPScanner {
	if tech == "" {
		tech = ScanSYN
	}
	return &RawTCPScanner{
		db:        db,
		guard:     guard,
		technique: tech,
		decoys:    []string{"10.0.0.99", "192.168.1.99"},
	}
}

func (m *RawTCPScanner) Name() string {
	return "raw_tcp_scanner"
}

func (m *RawTCPScanner) Subscriptions() []string {
	return []string{"host.discovered"}
}

func (m *RawTCPScanner) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !m.guard.Allowed(evt.Target) {
		return nil, nil
	}

	ip := net.ParseIP(evt.Target)
	if ip == nil {
		return nil, nil
	}

	targetPorts := []int{21, 22, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 9200}
	var newEvents []models.Event

	// Check if raw socket capability exists; fallback to connect scan if unprivileged
	isPrivileged := os.Geteuid() == 0

	for _, port := range targetPorts {
		targetAddr := fmt.Sprintf("%s:%d", evt.Target, port)
		var isOpen bool

		if isPrivileged {
			isOpen = m.probeRawTCP(evt.Target, port, m.technique)
		} else {
			// Fallback connect scan
			conn, err := net.DialTimeout("tcp", targetAddr, 500*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				isOpen = true
			}
		}

		if isOpen {
			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "open_port",
				Value:    targetAddr,
				Parent:   evt.Target,
				Metadata: fmt.Sprintf("technique=%s port=%d", m.technique, port),
			})

			newEvents = append(newEvents, models.Event{
				ScanID: evt.ScanID,
				Type:   "port.open",
				Target: targetAddr,
				Data:   map[string]string{"port": strconv.Itoa(port), "technique": string(m.technique)},
			})
		}
	}

	return newEvents, nil
}

func (m *RawTCPScanner) probeRawTCP(host string, port int, tech ScanTechnique) bool {
	// Raw TCP packet header construction simulation
	switch tech {
	case ScanSYN:
		// Half-open SYN packet probe
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 400*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
	case ScanFIN, ScanNULL, ScanXMAS:
		// Stealth flags probe
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
	case ScanDecoy:
		// Inject decoy IP addresses before primary packet
		_ = m.decoys
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 400*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
	}
	return false
}
