package modules

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

// RichProtocolScanner performs safe, non-intrusive service and protocol capability enumeration.
type RichProtocolScanner struct {
	db       store.RuntimeStore
	guard    scope.Guard
	timeout  time.Duration
	IMDSHost string
}

// NewRichProtocolScanner constructs a rich protocol scanner.
func NewRichProtocolScanner(db store.RuntimeStore, guard scope.Guard) *RichProtocolScanner {
	return &RichProtocolScanner{
		db:      db,
		guard:   guard,
		timeout: 3 * time.Second,
	}
}

func (s *RichProtocolScanner) Name() string {
	return "rich_protocol_scanner"
}

func (s *RichProtocolScanner) Subscriptions() []string {
	return []string{EventPort}
}

func (s *RichProtocolScanner) Handle(ctx context.Context, evt models.Event) ([]models.Event, error) {
	host, portStr, err := net.SplitHostPort(evt.Target)
	if err != nil {
		return nil, nil
	}
	if !s.guard.Allowed(host) {
		return nil, nil
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, nil
	}

	var events []models.Event
	scanID := evt.ScanID

	switch port {
	case 21: // FTP
		if res, err := s.ProbeFTP(ctx, host, port); err == nil && res != "" {
			s.recordService(ctx, scanID, host, port, "ftp", res)
		}
	case 22, 2222: // SSH
		if res, err := s.ProbeSSH(ctx, host, port); err == nil && res != "" {
			s.recordService(ctx, scanID, host, port, "ssh", res)
		}
	case 25, 587: // SMTP
		if res, err := s.ProbeSMTP(ctx, host, port); err == nil && res != "" {
			s.recordService(ctx, scanID, host, port, "smtp", res)
		}
	case 445, 139: // SMB
		if res, err := s.ProbeSMB(ctx, host, port); err == nil && res != "" {
			s.recordService(ctx, scanID, host, port, "smb", res)
		}
	case 3306: // MySQL
		if res, err := s.ProbeMySQL(ctx, host, port); err == nil && res != "" {
			s.recordService(ctx, scanID, host, port, "mysql", res)
		}
	case 5432: // PostgreSQL
		if res, err := s.ProbePostgres(ctx, host, port); err == nil && res != "" {
			s.recordService(ctx, scanID, host, port, "postgresql", res)
		}
	case 6379: // Redis
		if res, err := s.ProbeRedis(ctx, host, port); err == nil && res != "" {
			s.recordService(ctx, scanID, host, port, "redis", res)
		}
	}

	return events, nil
}

func (s *RichProtocolScanner) recordService(ctx context.Context, scanID, host string, port int, proto, detail string) {
	if s.db == nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(port))
	_ = s.db.AddAsset(ctx, models.Asset{
		ScanID:    scanID,
		Type:      "service_capability",
		Value:     target,
		Parent:    host,
		Metadata:  fmt.Sprintf("protocol=%s;capabilities=%s", proto, detail),
		CreatedAt: time.Now().UTC(),
	})
}

// ProbeSSH connects and retrieves the SSH identification banner.
func (s *RichProtocolScanner) ProbeSSH(ctx context.Context, host string, port int) (string, error) {
	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(s.timeout))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	banner = strings.TrimSpace(banner)

	// Send our safe client ID banner
	_, _ = conn.Write([]byte("SSH-2.0-Enumscan_1.0\r\n"))
	return banner, nil
}

// ProbeFTP connects, reads the 220 banner, and negotiates FEAT capabilities.
func (s *RichProtocolScanner) ProbeFTP(ctx context.Context, host string, port int) (string, error) {
	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(s.timeout))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	banner = strings.TrimSpace(banner)

	// Send FEAT command
	_, _ = conn.Write([]byte("FEAT\r\n"))
	var feats []string
	for i := 0; i < 10; i++ {
		line, err := reader.ReadString('\n')
		if err != nil || strings.HasPrefix(line, "211 End") || strings.HasPrefix(line, "500") {
			break
		}
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "211") {
			feats = append(feats, trimmed)
		}
	}
	_, _ = conn.Write([]byte("QUIT\r\n"))

	if len(feats) > 0 {
		return fmt.Sprintf("%s (features: %s)", banner, strings.Join(feats, ",")), nil
	}
	return banner, nil
}

// ProbeSMTP connects, reads the 220 banner, and sends EHLO.
func (s *RichProtocolScanner) ProbeSMTP(ctx context.Context, host string, port int) (string, error) {
	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(s.timeout))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	banner = strings.TrimSpace(banner)

	_, _ = conn.Write([]byte("EHLO enumscan.internal\r\n"))
	var ehloLines []string
	for i := 0; i < 8; i++ {
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "250") {
			break
		}
		ehloLines = append(ehloLines, strings.TrimSpace(line[4:]))
		if strings.HasPrefix(line, "250 ") {
			break
		}
	}
	_, _ = conn.Write([]byte("QUIT\r\n"))

	if len(ehloLines) > 0 {
		return fmt.Sprintf("%s (ehlo: %s)", banner, strings.Join(ehloLines, ",")), nil
	}
	return banner, nil
}

// ProbeSMB connects and sends an SMB2 NEGOTIATE packet to discover dialect without credentials.
func (s *RichProtocolScanner) ProbeSMB(ctx context.Context, host string, port int) (string, error) {
	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(s.timeout))

	// SMB2 negotiate request payload with standard NetBIOS header
	negReq := []byte{
		0x00, 0x00, 0x00, 0x44, // NetBIOS session length 68
		0xfe, 'S', 'M', 'B', // SMB2 magic
		0x40, 0x00, // Header length
		0x00, 0x00, // Credit charge
		0x00, 0x00, // Status
		0x00, 0x00, // Command (0 = Negotiate)
		0x00, 0x00, // Credits requested
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // Next command
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID
		0x00, 0x00, 0x00, 0x00, // Process ID
		0x00, 0x00, 0x00, 0x00, // Tree ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		// Negotiate body
		0x24, 0x00, // Structure size 36
		0x02, 0x00, // Dialect count (2)
		0x01, 0x00, // Security mode
		0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Client GUID
		0x02, 0x02, // Dialect 0x0202 (SMB 2.0.2)
		0x10, 0x02, // Dialect 0x0210 (SMB 2.1)
	}

	if _, err := conn.Write(negReq); err != nil {
		return "", err
	}

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n < 36 {
		return "", err
	}

	if bytes.Equal(resp[4:8], []byte{0xfe, 'S', 'M', 'B'}) {
		dialect := "SMB2/SMB3"
		if n >= 70 {
			rev := binary.LittleEndian.Uint16(resp[68:70])
			dialect = fmt.Sprintf("dialect=0x%04x", rev)
		}
		return fmt.Sprintf("SMB2 Server Confirmed (%s)", dialect), nil
	}

	return "", fmt.Errorf("non-SMB response")
}

// ProbeMySQL reads the initial MySQL server greeting and extracts the version string.
func (s *RichProtocolScanner) ProbeMySQL(ctx context.Context, host string, port int) (string, error) {
	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(s.timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < 5 {
		return "", err
	}

	// MySQL greeting packet: [3 bytes length][1 byte seq][1 byte proto][null-terminated version string]
	if buf[4] == 10 && n > 5 { // Protocol version 10
		end := bytes.IndexByte(buf[5:n], 0)
		if end > 0 {
			version := string(buf[5 : 5+end])
			return fmt.Sprintf("MySQL Server Protocol 10 (version: %s)", version), nil
		}
	}
	return "MySQL Handshake Detected", nil
}

// ProbePostgres negotiates an SSLRequest to identify PostgreSQL without authenticating.
func (s *RichProtocolScanner) ProbePostgres(ctx context.Context, host string, port int) (string, error) {
	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(s.timeout))

	// Send SSLRequest: [Int32(8)][Int32(80877103)]
	sslReq := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	if _, err := conn.Write(sslReq); err != nil {
		return "", err
	}

	reply := make([]byte, 1)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return "", err
	}

	if reply[0] == 'S' {
		return "PostgreSQL (SSL supported)", nil
	} else if reply[0] == 'N' {
		return "PostgreSQL (SSL not supported)", nil
	}

	return "", fmt.Errorf("unexpected Postgres reply: %c", reply[0])
}

// ProbeRedis sends PING to identify Redis.
func (s *RichProtocolScanner) ProbeRedis(ctx context.Context, host string, port int) (string, error) {
	d := net.Dialer{Timeout: s.timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(s.timeout))
	if _, err := conn.Write([]byte("PING\r\n")); err != nil {
		return "", err
	}

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "+PONG") {
		return "Redis (Unauthenticated access permitted: +PONG)", nil
	}
	if strings.HasPrefix(line, "-NOAUTH") {
		return "Redis (Password protected: -NOAUTH)", nil
	}
	return "Redis Handshake Detected", nil
}

// ProbeCloudIMDS queries standard link-local IMDS endpoints safely.
func (s *RichProtocolScanner) ProbeCloudIMDS(ctx context.Context, client *http.Client) (string, error) {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Second}
	}

	imdsBase := s.IMDSHost
	if imdsBase == "" {
		imdsBase = "http://169.254.169.254"
	}
	if !strings.HasPrefix(imdsBase, "http://") && !strings.HasPrefix(imdsBase, "https://") {
		imdsBase = "http://" + imdsBase
	}
	imdsBase = strings.TrimRight(imdsBase, "/")

	// 1. AWS IMDSv2 Token check
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, fmt.Sprintf("%s/latest/api/token", imdsBase), nil)
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return "AWS EC2 IMDSv2 Active", nil
		}
	}

	// 2. Azure IMDS
	reqAzure, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/metadata/instance?api-version=2021-02-01", imdsBase), nil)
	reqAzure.Header.Set("Metadata", "true")
	respAzure, err := client.Do(reqAzure)
	if err == nil {
		respAzure.Body.Close()
		if respAzure.StatusCode == http.StatusOK {
			return "Azure Instance Metadata Service Active", nil
		}
	}

	// 3. GCP IMDS
	reqGCP, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/computeMetadata/v1/", imdsBase), nil)
	reqGCP.Header.Set("Metadata-Flavor", "Google")
	respGCP, err := client.Do(reqGCP)
	if err == nil {
		respGCP.Body.Close()
		if respGCP.StatusCode == http.StatusOK {
			return "Google Cloud Compute Metadata Active", nil
		}
	}

	return "", fmt.Errorf("no cloud IMDS detected")
}
