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
	if d.config.EnableTCPSYNProbes {
		for _, port := range d.config.TCPProbePorts {
			if port < 1 || port > 65535 {
				continue
			}
			if tcpSYNHostResponsive(ctx, host, port) {
				_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "live_host", Value: host, Parent: parent, Metadata: fmt.Sprintf("method=tcp_syn_probe;port=%d", port)})
				break
			}
		}
	}
	if d.config.EnableTCPACKProbes {
		for _, port := range d.config.TCPProbePorts {
			if port < 1 || port > 65535 {
				continue
			}
			if tcpACKHostResponsive(ctx, host, port) {
				_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "live_host", Value: host, Parent: parent, Metadata: fmt.Sprintf("method=tcp_ack_probe;port=%d", port)})
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
	if d.config.EnableSNMPProbes {
		ports := d.config.SNMPProbePorts
		if len(ports) == 0 {
			ports = []int{161}
		}
		communities := d.config.SNMPCommunities
		if len(communities) == 0 {
			communities = []string{"public", "private"}
		}
		for _, port := range ports {
			for _, comm := range communities {
				if snmpHostResponsive(ctx, host, port, comm) {
					_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "live_host", Value: host, Parent: parent, Metadata: fmt.Sprintf("method=snmp_probe;port=%d;community=%s", port, comm)})
					break
				}
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

func tcpSYNHostResponsive(ctx context.Context, host string, port int) bool {
	if rawTCPSYNProbe(ctx, host, port) {
		return true
	}
	dialer := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err == nil {
		_ = conn.Close()
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

func rawTCPSYNProbe(ctx context.Context, host string, port int) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			return false
		}
		ip = net.ParseIP(addrs[0])
	}
	if ip == nil || ip.To4() == nil {
		return false
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)

	tv := syscall.Timeval{Sec: 0, Usec: 500000}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	packet := buildTCPHeader(12345, uint16(port), 0x02)

	var dstAddr [4]byte
	copy(dstAddr[:], ip.To4())
	sockaddr := &syscall.SockaddrInet4{Port: port, Addr: dstAddr}

	if err := syscall.Sendto(fd, packet, 0, sockaddr); err != nil {
		return false
	}

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || n < 40 {
			break
		}
		ipLen := int((buf[0] & 0x0f) * 4)
		if n < ipLen+20 {
			continue
		}
		tcpHeader := buf[ipLen : ipLen+20]
		srcPort := binary.BigEndian.Uint16(tcpHeader[0:2])
		if int(srcPort) == port {
			flags := tcpHeader[13]
			if flags&0x12 == 0x12 || flags&0x04 != 0 {
				return true
			}
		}
	}
	return false
}

func tcpACKHostResponsive(ctx context.Context, host string, port int) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil || len(addrs) == 0 {
			return false
		}
		ip = net.ParseIP(addrs[0])
	}
	if ip == nil || ip.To4() == nil {
		return false
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)

	tv := syscall.Timeval{Sec: 0, Usec: 500000}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	packet := buildTCPHeader(12346, uint16(port), 0x10)

	var dstAddr [4]byte
	copy(dstAddr[:], ip.To4())
	sockaddr := &syscall.SockaddrInet4{Port: port, Addr: dstAddr}

	if err := syscall.Sendto(fd, packet, 0, sockaddr); err != nil {
		return false
	}

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || n < 40 {
			break
		}
		ipLen := int((buf[0] & 0x0f) * 4)
		if n < ipLen+20 {
			continue
		}
		tcpHeader := buf[ipLen : ipLen+20]
		srcPort := binary.BigEndian.Uint16(tcpHeader[0:2])
		if int(srcPort) == port {
			flags := tcpHeader[13]
			if flags&0x04 != 0 {
				return true
			}
		}
	}
	return false
}

func buildTCPHeader(srcPort, dstPort uint16, flags byte) []byte {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	binary.BigEndian.PutUint32(hdr[4:8], 1000)
	binary.BigEndian.PutUint32(hdr[8:12], 0)
	hdr[12] = 0x50
	hdr[13] = flags
	binary.BigEndian.PutUint16(hdr[14:16], 64240)
	return hdr
}

func snmpHostResponsive(ctx context.Context, host string, port int, community string) bool {
	if community == "" {
		community = "public"
	}
	payload := buildSNMPGetRequest(community)
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
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 10 {
		return false
	}
	return buf[0] == 0x30
}

func buildSNMPGetRequest(community string) []byte {
	commBytes := []byte(community)
	oid := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
	nullVal := []byte{0x05, 0x00}

	varbind := append([]byte{0x30, byte(len(oid) + len(nullVal))}, oid...)
	varbind = append(varbind, nullVal...)

	varbindList := append([]byte{0x30, byte(len(varbind))}, varbind...)

	reqID := []byte{0x02, 0x04, 0x00, 0x00, 0x00, 0x01}
	errStatus := []byte{0x02, 0x01, 0x00}
	errIdx := []byte{0x02, 0x01, 0x00}

	pduPayload := append(reqID, errStatus...)
	pduPayload = append(pduPayload, errIdx...)
	pduPayload = append(pduPayload, varbindList...)

	pdu := append([]byte{0xa0, byte(len(pduPayload))}, pduPayload...)

	version := []byte{0x02, 0x01, 0x00}
	commHeader := append([]byte{0x04, byte(len(commBytes))}, commBytes...)

	msgBody := append(version, commHeader...)
	msgBody = append(msgBody, pdu...)

	return append([]byte{0x30, byte(len(msgBody))}, msgBody...)
}

func (d Discovery) captureLiveTraffic(ctx context.Context, scanID, parent string) []models.Event {
	htonsETH_P_ALL := uint16(0x0300)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htonsETH_P_ALL))
	if err != nil {
		_ = d.db.AddAsset(ctx, models.Asset{
			ScanID:   scanID,
			Type:     "discovery_note",
			Value:    parent,
			Metadata: "live_packet_capture_status=disabled_or_unprivileged",
		})
		return nil
	}
	defer syscall.Close(fd)

	dur := d.config.CaptureDurationMS
	if dur <= 0 {
		dur = 1000
	}
	sec := int64(dur / 1000)
	usec := int64((dur % 1000) * 1000)
	tv := syscall.Timeval{Sec: sec, Usec: usec}
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	buf := make([]byte, 4096)
	deadline := time.Now().Add(time.Duration(dur) * time.Millisecond)
	next := make([]models.Event, 0)
	seen := make(map[string]bool)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return next
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil || n < 14 {
			break
		}
		ethProto := binary.BigEndian.Uint16(buf[12:14])
		if ethProto == 0x0800 && n >= 34 {
			srcIP := net.IP(buf[26:30]).String()
			dstIP := net.IP(buf[30:34]).String()
			for _, ip := range []string{srcIP, dstIP} {
				if ip != "" && d.guard.Allowed(ip) && !seen[ip] {
					seen[ip] = true
					_ = d.db.AddAsset(ctx, models.Asset{
						ScanID:   scanID,
						Type:     "passive_observed_ip",
						Value:    ip,
						Parent:   parent,
						Metadata: "source=live_packet_capture",
					})
					next = append(next, models.Event{
						ScanID: scanID,
						Type:   EventHost,
						Target: ip,
						Data:   map[string]string{"source": "live_packet_capture"},
					})
				}
			}
		}
	}
	return next
}
