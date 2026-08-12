package modules

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
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
	mu       sync.Mutex
	timeout  time.Duration
	max      time.Duration
	failures int
}

type tcpScanResult struct {
	port     int
	address  string
	state    string
	latency  time.Duration
	timeout  time.Duration
	evidence string
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
	if config.MaxConcurrentPorts <= 0 {
		config.MaxConcurrentPorts = 4
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
	// Phase one is a bounded TCP-connect sweep. Only confirmed open ports reach
	// phase two, preventing banner probes from being sent to every candidate.
	jobs := make(chan int)
	results := make(chan tcpScanResult, len(p.config.TCPPorts))
	workers := p.config.MaxConcurrentPorts
	if workers > len(p.config.TCPPorts) {
		workers = len(p.config.TCPPorts)
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				results <- p.connectProbe(ctx, event.Target, port, timing)
			}
		}()
	}
	go func() {
		for _, port := range p.config.TCPPorts {
			select {
			case jobs <- port:
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				close(results)
				return
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	all := make([]tcpScanResult, 0, len(p.config.TCPPorts))
	for result := range results {
		all = append(all, result)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].port < all[j].port })
	next := make([]models.Event, 0)
	for _, result := range all {
		if result.state != "open" {
			if p.config.RecordClosedPorts {
				_ = p.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "port_state", Value: fmt.Sprintf("%s/tcp", result.address), Parent: event.Target, Metadata: fmt.Sprintf("state=%s;latency_ms=%d", result.state, result.latency.Milliseconds())})
			}
			continue
		}
		banner := ""
		if p.config.EnableBanner {
			banner = p.enrichTCP(ctx, result.address, result.port, timing.current())
		}
		metadata := fmt.Sprintf("protocol=tcp;state=open;phase=connect;latency_ms=%d;timeout_ms=%d", result.latency.Milliseconds(), result.timeout.Milliseconds())
		if banner != "" {
			metadata += ";banner=" + sanitizeMeta(banner)
		}
		value := fmt.Sprintf("%s/tcp", result.address)
		_ = p.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "open_port", Value: value, Parent: event.Target, Metadata: metadata})
		_ = p.db.AddPortObservation(ctx, models.PortObservation{ScanID: event.ScanID, Host: event.Target, Port: result.port, Protocol: "tcp", State: "open", LatencyMS: result.latency.Milliseconds(), Evidence: sanitizeMeta(banner)})
		next = append(next, models.Event{ScanID: event.ScanID, Type: EventPort, Target: result.address, Data: map[string]string{"port": strconv.Itoa(result.port), "protocol": "tcp", "banner": banner, "state": "open"}})
		next = append(next, webEvents(event.ScanID, result.address, result.port)...)
	}
	return next
}

func (p PortScan) connectProbe(ctx context.Context, host string, port int, timing *scanTiming) tcpScanResult {
	address, timeout := net.JoinHostPort(host, strconv.Itoa(port)), timing.current()
	start := time.Now()
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
	latency := time.Since(start)
	state := classifyTCPState(err)
	timing.observe(state == "open", latency)
	if conn != nil {
		_ = conn.Close()
	}
	return tcpScanResult{port: port, address: address, state: state, latency: latency, timeout: timeout, evidence: errorText(err)}
}

func (p PortScan) enrichTCP(ctx context.Context, address string, port int, timeout time.Duration) string {
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return ""
	}
	defer conn.Close()
	return grabBanner(conn, port, timeout)
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
		if readErr != nil || !validUDPResponse(port, buf[:n]) {
			continue
		}
		response := sanitizeMeta(string(buf[:n]))
		value := fmt.Sprintf("%s/udp", address)
		metadata := fmt.Sprintf("protocol=udp;state=open;probe=%s;latency_ms=%d;response=%s", udpProbeName(port), latency.Milliseconds(), response)
		_ = p.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "open_port", Value: value, Parent: event.Target, Metadata: metadata})
		_ = p.db.AddPortObservation(ctx, models.PortObservation{ScanID: event.ScanID, Host: event.Target, Port: port, Protocol: "udp", State: "open", LatencyMS: latency.Milliseconds(), Evidence: response})
		next = append(next, models.Event{ScanID: event.ScanID, Type: EventPort, Target: address, Data: map[string]string{"port": strconv.Itoa(port), "protocol": "udp", "response": response, "state": "open", "probe": udpProbeName(port)}})
	}
	return next
}

func (t *scanTiming) observe(success bool, latency time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
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

func (t *scanTiming) current() time.Duration { t.mu.Lock(); defer t.mu.Unlock(); return t.timeout }

func classifyTCPState(err error) string {
	if err == nil {
		return "open"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "closed"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT) {
		return "filtered"
	}
	return "unreachable"
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return sanitizeMeta(err.Error())
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
	case 69:
		return []byte{0, 1, 'e', 'n', 'u', 'm', 's', 'c', 'a', 'n', 0, 'o', 'c', 't', 'e', 't', 0} // TFTP RRQ
	case 111:
		return []byte{0x65, 0x6e, 0x75, 0x6d, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 0x86, 0xa0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	case 137:
		return []byte{0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, 'C', 'K', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 0, 0, 0x21, 0, 1}
	case 5060:
		return []byte("OPTIONS sip:scan@enumscan.invalid SIP/2.0\r\nVia: SIP/2.0/UDP enumscan.invalid;branch=z9hG4bK-enumscan\r\nFrom: <sip:scan@enumscan.invalid>;tag=1\r\nTo: <sip:scan@enumscan.invalid>\r\nCall-ID: enumscan\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 1\r\nContent-Length: 0\r\n\r\n")
	case 5353:
		return []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, '_', 'h', 't', 't', 'p', 4, '_', 't', 'c', 'p', 5, 'l', 'o', 'c', 'a', 'l', 0, 0, 12, 0, 1}
	case 1812:
		return []byte{1, 1, 0, 20, 0x65, 0x6e, 0x75, 0x6d, 0x73, 0x63, 0x61, 0x6e, 0, 1, 2, 3, 4, 5, 6, 7}
	case 1900:
		return []byte("M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n")
	default:
		return []byte("\r\n")
	}
}

func udpProbeName(port int) string {
	switch port {
	case 53:
		return "dns"
	case 69:
		return "tftp_rrq"
	case 111:
		return "rpcbind"
	case 123:
		return "ntp"
	case 137:
		return "netbios_name"
	case 161:
		return "snmp_get"
	case 500:
		return "ike"
	case 1812:
		return "radius_access_request"
	case 1900:
		return "ssdp"
	case 5060:
		return "sip_options"
	case 5353:
		return "mdns_ptr"
	default:
		return "generic"
	}
}

func validUDPResponse(port int, response []byte) bool {
	switch port {
	case 53, 5353:
		return len(response) >= 12 && (port == 5353 || response[2]&0x80 != 0)
	case 69:
		return len(response) >= 4 && response[0] == 0 && (response[1] == 3 || response[1] == 5)
	case 111:
		return len(response) >= 24
	case 123:
		return len(response) >= 48
	case 137:
		return len(response) >= 12 && response[0] == 0x12 && response[1] == 0x34
	case 1812:
		return len(response) >= 20 && (response[0] == 2 || response[0] == 3 || response[0] == 11)
	case 5060:
		return bytes.HasPrefix(response, []byte("SIP/2.0"))
	case 1900:
		return bytes.HasPrefix(response, []byte("HTTP/1.1"))
	default:
		return len(response) > 0
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
		return []int{21, 22, 25, 53, 80, 110, 111, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 2049, 2375, 2376, 2379, 3000, 3306, 3389, 5000, 5001, 5432, 5601, 5900, 5985, 5986, 6379, 6443, 8000, 8080, 8443, 8888, 9200, 9300, 10250, 10255, 11211, 27017}
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
