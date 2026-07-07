package modules

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type PortScan struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	config models.PortScanConfig
}

type scanTiming struct {
	timeout  time.Duration
	max      time.Duration
	failures int
}

func NewPortScan(db *store.SQLiteCLI, guard scope.Guard, config models.PortScanConfig) PortScan {
	if config.Profile == "" {
		config.Profile = "quick"
	}
	if config.BaseTimeoutMS <= 0 {
		config.BaseTimeoutMS = 750
	}
	if config.MaxTimeoutMS <= 0 {
		config.MaxTimeoutMS = 3000
	}
	if !config.EnableTCP && !config.EnableUDP {
		config.EnableTCP = true
	}
	config.TCPPorts = resolveTCPPorts(config.Profile, config.TCPPorts)
	config.UDPPorts = resolveUDPPorts(config.Profile, config.UDPPorts)
	return PortScan{db: db, guard: guard, config: config}
}

func (p PortScan) Name() string { return "portscan" }

func (p PortScan) Subscriptions() []string { return []string{EventHost} }

func (p PortScan) Handle(ctx context.Context, event models.Event) ([]models.Event, error) {
	if !p.guard.Allowed(event.Target) {
		return nil, nil
	}
	next := make([]models.Event, 0)
	if p.config.EnableRawSYN {
		p.recordRawSYNCapability(ctx, event.ScanID, event.Target)
	}
	timing := scanTiming{
		timeout: time.Duration(p.config.BaseTimeoutMS) * time.Millisecond,
		max:     time.Duration(p.config.MaxTimeoutMS) * time.Millisecond,
	}
	if p.config.EnableTCP {
		next = append(next, p.scanTCP(ctx, event, &timing)...)
	}
	if p.config.EnableUDP {
		next = append(next, p.scanUDP(ctx, event, &timing)...)
	}
	return next, nil
}

func (p PortScan) scanTCP(ctx context.Context, event models.Event, timing *scanTiming) []models.Event {
	next := make([]models.Event, 0)
	for _, port := range p.config.TCPPorts {
		address := net.JoinHostPort(event.Target, strconv.Itoa(port))
		start := time.Now()
		dialer := net.Dialer{Timeout: timing.timeout}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		latency := time.Since(start)
		timing.observe(err == nil, latency)
		if err != nil {
			continue
		}
		banner := ""
		if p.config.EnableBanner {
			banner = grabBanner(conn, port, timing.timeout)
		}
		_ = conn.Close()

		metadata := fmt.Sprintf("protocol=tcp;latency_ms=%d;timeout_ms=%d", latency.Milliseconds(), timing.timeout.Milliseconds())
		if banner != "" {
			metadata += ";banner=" + sanitizeMeta(banner)
		}
		value := fmt.Sprintf("%s/tcp", address)
		_ = p.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "open_port", Value: value, Parent: event.Target, Metadata: metadata})
		next = append(next, models.Event{ScanID: event.ScanID, Type: EventPort, Target: address, Data: map[string]string{"port": strconv.Itoa(port), "protocol": "tcp", "banner": banner}})
		next = append(next, webEvents(event.ScanID, address, port)...)
	}
	return next
}

func (p PortScan) scanUDP(ctx context.Context, event models.Event, timing *scanTiming) []models.Event {
	next := make([]models.Event, 0)
	for _, port := range p.config.UDPPorts {
		address := net.JoinHostPort(event.Target, strconv.Itoa(port))
		start := time.Now()
		conn, err := (&net.Dialer{Timeout: timing.timeout}).DialContext(ctx, "udp", address)
		if err != nil {
			timing.observe(false, time.Since(start))
			continue
		}
		payload := udpProbe(port)
		if len(payload) > 0 {
			_ = conn.SetDeadline(time.Now().Add(timing.timeout))
			_, _ = conn.Write(payload)
		}
		buf := make([]byte, 512)
		n, readErr := conn.Read(buf)
		_ = conn.Close()
		latency := time.Since(start)
		timing.observe(readErr == nil, latency)
		if readErr != nil {
			continue
		}
		response := sanitizeMeta(string(buf[:n]))
		value := fmt.Sprintf("%s/udp", address)
		metadata := fmt.Sprintf("protocol=udp;latency_ms=%d;response=%s", latency.Milliseconds(), response)
		_ = p.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "open_port", Value: value, Parent: event.Target, Metadata: metadata})
		next = append(next, models.Event{ScanID: event.ScanID, Type: EventPort, Target: address, Data: map[string]string{"port": strconv.Itoa(port), "protocol": "udp", "response": response}})
	}
	return next
}

func (p PortScan) recordRawSYNCapability(ctx context.Context, scanID, target string) {
	status := "unavailable"
	if os.Geteuid() == 0 {
		status = "privileged_raw_socket_possible"
	}
	_ = p.db.AddAsset(ctx, models.Asset{
		ScanID:   scanID,
		Type:     "scan_capability",
		Value:    "raw_syn",
		Parent:   target,
		Metadata: "status=" + status + ";note=dependency_free_scaffold_uses_tcp_connect_scan",
	})
}

func (t *scanTiming) observe(success bool, latency time.Duration) {
	if success {
		t.failures = 0
		next := latency * 4
		if next < 250*time.Millisecond {
			next = 250 * time.Millisecond
		}
		if next > t.max {
			next = t.max
		}
		t.timeout = next
		return
	}
	t.failures++
	if t.failures > 0 && t.failures%25 == 0 {
		t.timeout *= 2
		if t.timeout > t.max {
			t.timeout = t.max
		}
	}
}

func grabBanner(conn net.Conn, port int, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if request := bannerProbe(port); request != "" {
		_, _ = conn.Write([]byte(request))
	}
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(line)
}

func bannerProbe(port int) string {
	switch port {
	case 80, 8000, 8080, 8081, 8888:
		return "HEAD / HTTP/1.0\r\n\r\n"
	case 25, 587:
		return "EHLO enumscan.local\r\n"
	case 110, 143, 21:
		return "\r\n"
	default:
		return ""
	}
}

func udpProbe(port int) []byte {
	switch port {
	case 53:
		return []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01}
	case 123:
		return []byte{0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	case 161:
		return []byte{0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', 0xa0, 0x19, 0x02, 0x04, 0x70, 0x65, 0x6e, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00}
	case 500:
		return []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x10, 0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
	case 1900:
		return []byte("M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n")
	default:
		return []byte("\r\n")
	}
}

func webEvents(scanID, address string, port int) []models.Event {
	switch port {
	case 80, 8000, 8080, 8081, 8888:
		return []models.Event{{ScanID: scanID, Type: EventHTTPURL, Target: "http://" + address}}
	case 443, 8443:
		return []models.Event{{ScanID: scanID, Type: EventHTTPURL, Target: "https://" + address}}
	default:
		return nil
	}
}

func resolveTCPPorts(profile string, override []int) []int {
	if len(override) > 0 {
		return uniquePorts(override)
	}
	switch strings.ToLower(profile) {
	case "exhaustive", "full":
		ports := make([]int, 0, 65535)
		for port := 1; port <= 65535; port++ {
			ports = append(ports, port)
		}
		return ports
	case "standard":
		return []int{21, 22, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 5432, 5601, 5900, 5985, 5986, 6379, 6443, 8000, 8080, 8443, 8888, 9200, 9300, 11211, 27017}
	default:
		return []int{22, 80, 443, 8000, 8080, 8443}
	}
}

func resolveUDPPorts(profile string, override []int) []int {
	if len(override) > 0 {
		return uniquePorts(override)
	}
	switch strings.ToLower(profile) {
	case "exhaustive", "full":
		ports := make([]int, 0, 65535)
		for port := 1; port <= 65535; port++ {
			ports = append(ports, port)
		}
		return ports
	case "standard":
		return []int{53, 67, 68, 69, 88, 111, 123, 137, 138, 161, 162, 389, 500, 514, 520, 623, 1812, 1813, 1900, 4500, 5060, 5353, 5683}
	default:
		return []int{53, 123, 161, 500, 1900}
	}
}

func uniquePorts(ports []int) []int {
	seen := make(map[int]bool)
	out := make([]int, 0, len(ports))
	for _, port := range ports {
		if port < 1 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		out = append(out, port)
	}
	return out
}

func sanitizeMeta(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, ";", ",")
	value = strings.TrimSpace(value)
	if len(value) > 180 {
		return value[:180]
	}
	return value
}
