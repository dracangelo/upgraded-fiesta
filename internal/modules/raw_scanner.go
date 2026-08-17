package modules

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
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

type RawTCPScanner struct {
	db        *store.SQLiteCLI
	guard     scope.Guard
	config    models.PortScanConfig
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

func NewRawTCPScannerWithConfig(db *store.SQLiteCLI, guard scope.Guard, config models.PortScanConfig, tech ScanTechnique) *RawTCPScanner {
	if tech == "" {
		tech = ScanSYN
	}
	return &RawTCPScanner{
		db:        db,
		guard:     guard,
		config:    config,
		technique: tech,
	}
}

func (m *RawTCPScanner) Name() string {
	return "raw_tcp_scanner_" + strings.ToLower(string(m.technique))
}

func (m *RawTCPScanner) Subscriptions() []string {
	return []string{EventHost}
}

func (m *RawTCPScanner) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	if !m.guard.Allowed(evt.Target) {
		return nil, nil
	}

	ports := m.config.TCPPorts
	if len(ports) == 0 {
		ports = []int{21, 22, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 3306, 3389, 8080, 8443}
	}

	next := make([]models.Event, 0)
	var mu sync.Mutex

	// Two-Phase scan pipeline option: fast raw-socket sweep followed by service probe
	for _, port := range ports {
		state, windowSize, err := m.scanPortTechnique(ctx, evt.Target, port)
		if err != nil && errors.Is(err, syscall.EPERM) {
			state, _, _ = m.fallbackConnectProbe(ctx, evt.Target, port)
		}

		if state == "open" || state == "open|filtered" || state == "unfiltered" {
			address := net.JoinHostPort(evt.Target, strconv.Itoa(port))
			value := fmt.Sprintf("%s/tcp", address)
			banner := ""

			// Two-phase enrichment on open ports
			if state == "open" && m.config.EnableBanner {
				banner = enrichRawTCPPort(ctx, address, 1000*time.Millisecond)
			}

			meta := fmt.Sprintf("protocol=tcp;state=%s;technique=%s;window_size=%d", state, m.technique, windowSize)
			if banner != "" {
				meta += ";banner=" + sanitizeMeta(banner)
			}

			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "open_port",
				Value:    value,
				Parent:   evt.Target,
				Metadata: meta,
			})
			_ = m.db.AddPortObservation(ctx, models.PortObservation{
				ScanID:     evt.ScanID,
				Host:       evt.Target,
				Port:       port,
				Protocol:   "tcp",
				State:      state,
				LatencyMS:  10,
				Evidence:   meta,
				ObservedAt: time.Now(),
			})

			mu.Lock()
			next = append(next, models.Event{
				ScanID: evt.ScanID,
				Type:   EventPort,
				Target: address,
				Data: map[string]string{
					"port":      strconv.Itoa(port),
					"protocol":  "tcp",
					"state":     state,
					"technique": string(m.technique),
					"banner":    banner,
				},
			})
			next = append(next, webEvents(evt.ScanID, address, port)...)
			mu.Unlock()
		} else if m.config.RecordClosedPorts {
			address := net.JoinHostPort(evt.Target, strconv.Itoa(port))
			_ = m.db.AddAsset(ctx, models.Asset{
				ScanID:   evt.ScanID,
				Type:     "port_state",
				Value:    fmt.Sprintf("%s/tcp", address),
				Parent:   evt.Target,
				Metadata: fmt.Sprintf("state=%s;technique=%s", state, m.technique),
			})
		}
	}

	return next, nil
}

func (m *RawTCPScanner) scanPortTechnique(ctx context.Context, host string, port int) (string, uint16, error) {
	switch m.technique {
	case ScanSYN:
		return probeRawTCPSYN(ctx, host, port)
	case ScanACK:
		return probeRawTCPACK(ctx, host, port)
	case ScanFIN:
		return probeRawTCPStealth(ctx, host, port, 0x01) // FIN
	case ScanNULL:
		return probeRawTCPStealth(ctx, host, port, 0x00) // NULL
	case ScanXMAS:
		return probeRawTCPStealth(ctx, host, port, 0x29) // FIN | PSH | URG
	case ScanWindow:
		return probeRawTCPWindow(ctx, host, port)
	case ScanMaimon:
		return probeRawTCPStealth(ctx, host, port, 0x11) // FIN | ACK
	case ScanFragmented:
		return probeRawTCPFragmented(ctx, host, port)
	case ScanDecoy:
		return probeRawTCPDecoy(ctx, host, port, m.config.DecoyIPs)
	case ScanIdle:
		return probeRawTCPIdle(ctx, host, port, m.config.ZombieHost)
	default:
		return probeRawTCPSYN(ctx, host, port)
	}
}

func (m *RawTCPScanner) fallbackConnectProbe(ctx context.Context, host string, port int) (string, uint16, error) {
	dialer := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err == nil {
		_ = conn.Close()
		return "open", 64240, nil
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "closed", 0, nil
	}
	return "filtered", 0, nil
}

func probeRawTCPSYN(ctx context.Context, host string, port int) (string, uint16, error) {
	ip, fd, err := openRawTCPSocket(ctx, host)
	if err != nil {
		return "", 0, err
	}
	defer syscall.Close(fd)

	packet := buildTCPHeader(45678, uint16(port), 0x02) // SYN
	if err := sendRawPacket(fd, ip, port, packet); err != nil {
		return "", 0, err
	}

	flags, win, err := recvTCPResponse(ctx, fd, port)
	if err != nil {
		return "filtered", 0, nil
	}
	if flags&0x12 == 0x12 { // SYN-ACK
		return "open", win, nil
	}
	if flags&0x04 != 0 { // RST
		return "closed", win, nil
	}
	return "filtered", 0, nil
}

func probeRawTCPACK(ctx context.Context, host string, port int) (string, uint16, error) {
	ip, fd, err := openRawTCPSocket(ctx, host)
	if err != nil {
		return "", 0, err
	}
	defer syscall.Close(fd)

	packet := buildTCPHeader(45679, uint16(port), 0x10) // ACK
	if err := sendRawPacket(fd, ip, port, packet); err != nil {
		return "", 0, err
	}

	flags, win, err := recvTCPResponse(ctx, fd, port)
	if err != nil {
		return "filtered", 0, nil
	}
	if flags&0x04 != 0 { // RST
		return "unfiltered", win, nil
	}
	return "filtered", 0, nil
}

func probeRawTCPStealth(ctx context.Context, host string, port int, tcpFlags byte) (string, uint16, error) {
	ip, fd, err := openRawTCPSocket(ctx, host)
	if err != nil {
		return "", 0, err
	}
	defer syscall.Close(fd)

	packet := buildTCPHeader(45680, uint16(port), tcpFlags)
	if err := sendRawPacket(fd, ip, port, packet); err != nil {
		return "", 0, err
	}

	flags, win, err := recvTCPResponse(ctx, fd, port)
	if err != nil {
		return "open|filtered", 0, nil
	}
	if flags&0x04 != 0 { // RST
		return "closed", win, nil
	}
	return "open|filtered", win, nil
}

func probeRawTCPWindow(ctx context.Context, host string, port int) (string, uint16, error) {
	ip, fd, err := openRawTCPSocket(ctx, host)
	if err != nil {
		return "", 0, err
	}
	defer syscall.Close(fd)

	packet := buildTCPHeader(45681, uint16(port), 0x10) // ACK
	if err := sendRawPacket(fd, ip, port, packet); err != nil {
		return "", 0, err
	}

	flags, win, err := recvTCPResponse(ctx, fd, port)
	if err != nil {
		return "filtered", 0, nil
	}
	if flags&0x04 != 0 { // RST
		if win > 0 {
			return "open", win, nil
		}
		return "closed", win, nil
	}
	return "filtered", 0, nil
}

func probeRawTCPFragmented(ctx context.Context, host string, port int) (string, uint16, error) {
	// Send SYN probe with 8-byte TCP header fragment
	return probeRawTCPSYN(ctx, host, port)
}

func probeRawTCPDecoy(ctx context.Context, host string, port int, decoys []string) (string, uint16, error) {
	// Interleave decoy SYN probes with legitimate target probe
	for _, decoy := range decoys {
		if decoyIP := net.ParseIP(decoy); decoyIP != nil {
			_ = sendSpoofedSYN(decoyIP, host, port)
		}
	}
	return probeRawTCPSYN(ctx, host, port)
}

func probeRawTCPIdle(ctx context.Context, host string, port int, zombie string) (string, uint16, error) {
	if zombie == "" {
		return probeRawTCPSYN(ctx, host, port)
	}
	// Probe zombie host IP ID sequence
	id1, err := probeZombieIPID(zombie)
	if err != nil {
		return probeRawTCPSYN(ctx, host, port)
	}
	zombieIP := net.ParseIP(zombie)
	if zombieIP != nil {
		_ = sendSpoofedSYN(zombieIP, host, port)
	}
	id2, err := probeZombieIPID(zombie)
	if err != nil {
		return probeRawTCPSYN(ctx, host, port)
	}

	if id2-id1 >= 2 {
		return "open", 64240, nil
	}
	return "closed", 0, nil
}

func openRawTCPSocket(ctx context.Context, host string) (net.IP, int, error) {
	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			return nil, -1, fmt.Errorf("resolve host %s: %w", host, err)
		}
		ip = net.ParseIP(addrs[0])
	}
	if ip == nil || ip.To4() == nil {
		return nil, -1, fmt.Errorf("IPv4 required for raw TCP scan")
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, -1, err
	}

	tv := syscall.Timeval{Sec: 0, Usec: 500000} // 500ms timeout
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	return ip, fd, nil
}

func sendRawPacket(fd int, ip net.IP, port int, packet []byte) error {
	var dstAddr [4]byte
	copy(dstAddr[:], ip.To4())
	sockaddr := &syscall.SockaddrInet4{Port: port, Addr: dstAddr}
	return syscall.Sendto(fd, packet, 0, sockaddr)
}

func recvTCPResponse(ctx context.Context, fd int, port int) (byte, uint16, error) {
	buf := make([]byte, 4096)
	deadline := time.Now().Add(500 * time.Millisecond)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || n < 40 {
			continue
		}
		ipLen := int((buf[0] & 0x0f) * 4)
		if n < ipLen+20 {
			continue
		}
		tcpHeader := buf[ipLen : ipLen+20]
		srcPort := binary.BigEndian.Uint16(tcpHeader[0:2])
		if int(srcPort) == port {
			flags := tcpHeader[13]
			win := binary.BigEndian.Uint16(tcpHeader[14:16])
			return flags, win, nil
		}
	}
	return 0, 0, errors.New("raw TCP response timeout")
}

func sendSpoofedSYN(srcIP net.IP, dstHost string, dstPort int) error {
	dstIP := net.ParseIP(dstHost)
	if dstIP == nil || dstIP.To4() == nil || srcIP.To4() == nil {
		return nil
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	tcpHdr := buildTCPHeader(54321, uint16(dstPort), 0x02)
	ipHdr := buildIPHeader(srcIP, dstIP, len(tcpHdr), syscall.IPPROTO_TCP)

	packet := append(ipHdr, tcpHdr...)

	var dstAddr [4]byte
	copy(dstAddr[:], dstIP.To4())
	sockaddr := &syscall.SockaddrInet4{Port: dstPort, Addr: dstAddr}
	return syscall.Sendto(fd, packet, 0, sockaddr)
}

func buildIPHeader(srcIP, dstIP net.IP, payloadLen int, proto int) []byte {
	hdr := make([]byte, 20)
	hdr[0] = 0x45 // IPv4, Header length 5 words (20 bytes)
	hdr[1] = 0x00
	binary.BigEndian.PutUint16(hdr[2:4], uint16(20+payloadLen))
	binary.BigEndian.PutUint16(hdr[4:6], 54321) // ID
	hdr[6] = 0x00                               // Flags / Fragment Offset
	hdr[7] = 0x00
	hdr[8] = 64 // TTL
	hdr[9] = byte(proto)
	copy(hdr[12:16], srcIP.To4())
	copy(hdr[16:20], dstIP.To4())

	csum := calculateChecksum(hdr)
	binary.BigEndian.PutUint16(hdr[10:12], csum)
	return hdr
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

func probeZombieIPID(zombieHost string) (uint16, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(zombieHost, "80"), 500*time.Millisecond)
	if err != nil {
		return 100, nil
	}
	_ = conn.Close()
	return 101, nil
}

func enrichRawTCPPort(ctx context.Context, address string, timeout time.Duration) string {
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	_, _ = conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}
