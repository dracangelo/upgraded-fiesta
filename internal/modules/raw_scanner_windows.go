//go:build windows

package modules

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
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
	ScanWindow     ScanTechnique = "WINDOW"
	ScanMaimon     ScanTechnique = "MAIMON"
)

// RawTCPScanner retains the same module contract on Windows, but performs
// bounded TCP-connect observations instead of raw packets. Windows raw socket
// restrictions make SYN/ACK/stealth interpretation unreliable; pretending
// otherwise would create misleading evidence.
type RawTCPScanner struct {
	db        store.RuntimeStore
	guard     scope.Guard
	config    models.PortScanConfig
	technique ScanTechnique
}

func NewRawTCPScanner(db store.RuntimeStore, guard scope.Guard, technique ScanTechnique) *RawTCPScanner {
	return NewRawTCPScannerWithConfig(db, guard, models.PortScanConfig{}, technique)
}

func NewRawTCPScannerWithConfig(db store.RuntimeStore, guard scope.Guard, config models.PortScanConfig, technique ScanTechnique) *RawTCPScanner {
	if technique == "" {
		technique = ScanSYN
	}
	return &RawTCPScanner{db: db, guard: guard, config: config, technique: technique}
}

func (m *RawTCPScanner) Name() string {
	return "raw_tcp_scanner_" + strings.ToLower(string(m.technique))
}
func (m *RawTCPScanner) Subscriptions() []string { return []string{EventHost} }

func (m *RawTCPScanner) Handle(ctx context.Context, event models.Event) ([]models.Event, error) {
	if !m.guard.Allowed(event.Target) {
		return nil, nil
	}
	ports := m.config.TCPPorts
	if len(ports) == 0 {
		ports = []int{21, 22, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 3306, 3389, 8080, 8443}
	}
	next := make([]models.Event, 0)
	for _, port := range ports {
		state, windowSize, _ := m.fallbackConnectProbe(ctx, event.Target, port)
		if state != "open" {
			if m.config.RecordClosedPorts {
				address := net.JoinHostPort(event.Target, strconv.Itoa(port))
				_ = m.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "port_state", Value: fmt.Sprintf("%s/tcp", address), Parent: event.Target, Metadata: fmt.Sprintf("state=%s;technique=%s;transport=tcp_connect_fallback", state, m.technique)})
			}
			continue
		}
		address := net.JoinHostPort(event.Target, strconv.Itoa(port))
		banner := ""
		if m.config.EnableBanner {
			banner = enrichRawTCPPort(ctx, address, time.Second)
		}
		metadata := fmt.Sprintf("protocol=tcp;state=open;technique=%s;window_size=%d;transport=tcp_connect_fallback", m.technique, windowSize)
		if banner != "" {
			metadata += ";banner=" + sanitizeMeta(banner)
		}
		_ = m.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "open_port", Value: fmt.Sprintf("%s/tcp", address), Parent: event.Target, Metadata: metadata})
		_ = m.db.AddPortObservation(ctx, models.PortObservation{ScanID: event.ScanID, Host: event.Target, Port: port, Protocol: "tcp", State: "open", LatencyMS: 0, Evidence: metadata, ObservedAt: time.Now()})
		next = append(next, models.Event{ScanID: event.ScanID, Type: EventPort, Target: address, Data: map[string]string{"port": strconv.Itoa(port), "protocol": "tcp", "state": "open", "technique": string(m.technique), "banner": banner}})
		next = append(next, webEvents(event.ScanID, address, port)...)
	}
	return next, nil
}

func (m *RawTCPScanner) fallbackConnectProbe(ctx context.Context, host string, port int) (string, uint16, error) {
	connection, err := (&net.Dialer{Timeout: 500 * time.Millisecond}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err == nil {
		_ = connection.Close()
		return "open", 0, nil
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "closed", 0, nil
	}
	return "filtered", 0, nil
}

func buildIPHeader(sourceIP, destinationIP net.IP, payloadLength int, protocol int) []byte {
	header := make([]byte, 20)
	header[0] = 0x45
	binary.BigEndian.PutUint16(header[2:4], uint16(20+payloadLength))
	binary.BigEndian.PutUint16(header[4:6], 54321)
	header[8] = 64
	header[9] = byte(protocol)
	copy(header[12:16], sourceIP.To4())
	copy(header[16:20], destinationIP.To4())
	binary.BigEndian.PutUint16(header[10:12], calculateChecksum(header))
	return header
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for index := 0; index < len(data)-1; index += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[index : index+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

func enrichRawTCPPort(ctx context.Context, address string, timeout time.Duration) string {
	connection, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return ""
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 512)
	count, _ := connection.Read(buffer)
	return strings.TrimSpace(string(buffer[:count]))
}
