package modules

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"enumscan/internal/models"
)

// discoverDNSRecords collects resolver-visible records only when the operator
// opts in to DNS discovery. It does not use a third-party DNS-over-HTTP API.
func (d Discovery) discoverDNSRecords(ctx context.Context, scanID, domain string) {
	if !d.config.EnableDNSRecords {
		return
	}
	if txt, err := net.DefaultResolver.LookupTXT(ctx, domain); err == nil {
		for _, value := range txt {
			typeName := "dns_txt"
			lower := strings.ToLower(value)
			if strings.HasPrefix(lower, "v=spf1") {
				typeName = "dns_spf"
			}
			_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: typeName, Value: value, Parent: domain, Metadata: "source=dns_txt"})
		}
	}
	if txt, err := net.DefaultResolver.LookupTXT(ctx, "_dmarc."+domain); err == nil {
		for _, value := range txt {
			_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "dns_dmarc", Value: value, Parent: domain, Metadata: "source=dns_txt"})
		}
	}
	for _, service := range []struct{ service, proto string }{{"_http", "_tcp"}, {"_https", "_tcp"}, {"_sip", "_tcp"}, {"_sip", "_udp"}, {"_xmpp-client", "_tcp"}} {
		_, records, err := net.DefaultResolver.LookupSRV(ctx, service.service, service.proto, domain)
		if err != nil {
			continue
		}
		for _, record := range records {
			target := strings.TrimSuffix(record.Target, ".")
			if !d.guard.Allowed(target) {
				continue
			}
			_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "dns_srv", Value: target, Parent: domain, Metadata: fmt.Sprintf("service=%s.%s;port=%d;priority=%d;weight=%d", service.service, service.proto, record.Port, record.Priority, record.Weight)})
		}
	}
}

// probeLiveHost adds positive liveness evidence. It never interprets a timeout
// as a dead host, because firewalls commonly drop discovery probes.
func (d Discovery) probeLiveHost(ctx context.Context, scanID, host, parent string) {
	if d.config.EnableICMPSweep && pingHost(ctx, host) {
		_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "live_host", Value: host, Parent: parent, Metadata: "method=icmp_echo"})
	}
	if d.config.EnableTCPHostProbes {
		for _, port := range d.config.TCPProbePorts {
			if port < 1 || port > 65535 {
				continue
			}
			if tcpHostResponsive(ctx, host, port) {
				_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "live_host", Value: host, Parent: parent, Metadata: fmt.Sprintf("method=tcp_connect;port=%d", port)})
				break
			}
		}
	}
	if d.config.EnableUDPLiveProbes {
		for _, port := range d.config.UDPProbePorts {
			if udpHostResponsive(ctx, host, port) {
				_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "live_host", Value: host, Parent: parent, Metadata: fmt.Sprintf("method=udp_application_probe;port=%d", port)})
				break
			}
		}
	}
}

func pingHost(ctx context.Context, host string) bool {
	// The platform ping utility performs a real ICMP echo without embedding a
	// privileged raw-socket implementation in enumscan.
	args := []string{"-c", "1", "-W", "1", host}
	if net.ParseIP(host) != nil && strings.Contains(host, ":") {
		args = []string{"-6", "-c", "1", "-W", "1", host}
	}
	return exec.CommandContext(ctx, "ping", args...).Run() == nil
}

func tcpHostResponsive(ctx context.Context, host string, port int) bool {
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err == nil {
		_ = conn.Close()
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

func udpHostResponsive(ctx context.Context, host string, port int) bool {
	var payload []byte
	switch port {
	case 53:
		payload = dnsProbePayload()
	case 123:
		payload = make([]byte, 48)
		payload[0] = 0x1b
	default:
		return false // only protocol-valid discovery probes are sent.
	}
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return false
	}
	if _, err := conn.Write(payload); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	if port == 53 {
		return n >= 12 && buf[2]&0x80 != 0
	}
	return n >= 48
}

func dnsProbePayload() []byte {
	buf := make([]byte, 17)
	binary.BigEndian.PutUint16(buf[0:2], 0xE11D)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	buf[12] = 1
	buf[13] = 'a'
	buf[14] = 0
	binary.BigEndian.PutUint16(buf[15:17], 1)
	return append(buf, 0, 1) // QTYPE A, QCLASS IN
}

var captureIP = regexp.MustCompile(`(?i)(?:\b(?:ip6?|arp)\s+)?(?:\[)?([0-9a-f:.]{2,})\]?`)
var captureHost = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b`)

// importCaptureObservations imports existing tcpdump/tshark text exports. It
// is intentionally offline: live packet capture requires explicit platform
// privileges and is not silently attempted by a scan.
func (d Discovery) importCaptureObservations(ctx context.Context, scanID, parent string) []models.Event {
	next, seen := make([]models.Event, 0), map[string]bool{}
	for _, path := range d.config.PassiveCaptureFiles {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 4096), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			for _, match := range captureIP.FindAllStringSubmatch(line, -1) {
				value := normalizeCaptureIP(match[1])
				if net.ParseIP(value) == nil || !d.guard.Allowed(value) || seen[value] {
					continue
				}
				seen[value] = true
				_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "passive_observed_ip", Value: value, Parent: parent, Metadata: "source=packet_capture_import"})
				next = append(next, models.Event{ScanID: scanID, Type: EventHost, Target: value, Data: map[string]string{"source": "packet_capture_import"}})
			}
			for _, value := range captureHost.FindAllString(line, -1) {
				value = strings.ToLower(strings.TrimSuffix(value, "."))
				if !sameDomain(parent, value) || !d.guard.Allowed(value) || seen[value] {
					continue
				}
				seen[value] = true
				_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "passive_observed_host", Value: value, Parent: parent, Metadata: "source=packet_capture_import"})
				next = append(next, models.Event{ScanID: scanID, Type: EventTarget, Target: value, Data: map[string]string{"source": "packet_capture_import"}})
			}
		}
		_ = file.Close()
	}
	return next
}

func normalizeCaptureIP(value string) string {
	value = strings.Trim(value, "[]")
	if net.ParseIP(value) != nil {
		return value
	}
	// tcpdump writes IPv4 endpoints as 192.0.2.1.443. Strip the final
	// dot-port segment only when what remains is a valid IP address.
	if strings.Count(value, ".") == 4 {
		if index := strings.LastIndex(value, "."); index > 0 && net.ParseIP(value[:index]) != nil {
			return value[:index]
		}
	}
	return ""
}
