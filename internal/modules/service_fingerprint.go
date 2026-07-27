package modules

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type ServiceFingerprint struct {
	db    *store.SQLiteCLI
	guard scope.Guard
}

type serviceID struct {
	Name       string
	Version    string
	Product    string
	CPE        string
	Confidence string
	Evidence   string
}

func NewServiceFingerprint(db *store.SQLiteCLI, guard scope.Guard) ServiceFingerprint {
	return ServiceFingerprint{db: db, guard: guard}
}

func (s ServiceFingerprint) Name() string { return "service_fingerprint" }

func (s ServiceFingerprint) Subscriptions() []string { return []string{EventPort} }

func (s ServiceFingerprint) Handle(ctx context.Context, event models.Event) ([]models.Event, error) {
	host, port, err := net.SplitHostPort(event.Target)
	if err != nil {
		return nil, nil
	}
	if !s.guard.Allowed(host) {
		return nil, nil
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return nil, nil
	}
	protocol := event.Data["protocol"]
	fp := fingerprintFromPort(portNum, protocol)
	if banner := firstNonEmpty(event.Data["banner"], event.Data["response"]); banner != "" {
		fp = refineFromEvidence(fp, banner)
	}
	if active := activeProbe(ctx, event.Target, portNum, protocol); active.Evidence != "" {
		fp = mergeFingerprint(fp, active)
	}
	if fp.Name == "" {
		return nil, nil
	}
	metadata := serviceMetadata(fp, portNum, protocol)
	_ = s.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "service", Value: fp.Name, Parent: event.Target, Metadata: metadata})
	if fp.Version != "" {
		_ = s.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "service_version", Value: fp.Version, Parent: event.Target, Metadata: metadata})
	}
	if fp.CPE != "" {
		_ = s.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "cpe_candidate", Value: fp.CPE, Parent: event.Target, Metadata: "confidence=" + fp.Confidence + ";evidence=" + cleanEvidence(fp.Evidence)})
	}
	return []models.Event{{ScanID: event.ScanID, Type: EventService, Target: event.Target, Data: map[string]string{"service": fp.Name, "version": fp.Version, "cpe": fp.CPE, "confidence": fp.Confidence}}}, nil
}

func fingerprintFromPort(port int, protocol string) serviceID {
	table := map[int]serviceID{
		21:    {Name: "ftp", CPE: "cpe:/a:ftp:ftp", Confidence: "low"},
		22:    {Name: "ssh", CPE: "cpe:/a:openssh:openssh", Confidence: "medium"},
		25:    {Name: "smtp", CPE: "cpe:/a:smtp:smtp", Confidence: "low"},
		53:    {Name: "dns", CPE: "cpe:/a:isc:bind", Confidence: "low"},
		80:    {Name: "http", CPE: "cpe:/a:http:http_server", Confidence: "low"},
		110:   {Name: "pop3", CPE: "cpe:/a:pop3:pop3", Confidence: "low"},
		111:   {Name: "rpcbind", CPE: "cpe:/a:rpcbind:rpcbind", Confidence: "medium"},
		135:   {Name: "msrpc", CPE: "cpe:/o:microsoft:windows", Confidence: "low"},
		139:   {Name: "netbios-ssn", CPE: "cpe:/o:microsoft:windows", Confidence: "low"},
		143:   {Name: "imap", CPE: "cpe:/a:imap:imap", Confidence: "low"},
		389:   {Name: "ldap", CPE: "cpe:/a:openldap:openldap", Confidence: "low"},
		443:   {Name: "https", CPE: "cpe:/a:http:http_server", Confidence: "low"},
		445:   {Name: "smb", CPE: "cpe:/o:microsoft:windows", Confidence: "medium"},
		465:   {Name: "smtps", CPE: "cpe:/a:smtp:smtp", Confidence: "low"},
		500:   {Name: "ike", CPE: "cpe:/a:ipsec:ipsec", Confidence: "medium"},
		587:   {Name: "smtp-submission", CPE: "cpe:/a:smtp:smtp", Confidence: "low"},
		636:   {Name: "ldaps", CPE: "cpe:/a:openldap:openldap", Confidence: "low"},
		993:   {Name: "imaps", CPE: "cpe:/a:imap:imap", Confidence: "low"},
		995:   {Name: "pop3s", CPE: "cpe:/a:pop3:pop3", Confidence: "low"},
		1433:  {Name: "mssql", CPE: "cpe:/a:microsoft:sql_server", Confidence: "medium"},
		1521:  {Name: "oracle-tns", CPE: "cpe:/a:oracle:database", Confidence: "medium"},
		1812:  {Name: "radius", CPE: "cpe:/a:freeradius:freeradius", Confidence: "low"},
		1813:  {Name: "radius-acct", CPE: "cpe:/a:freeradius:freeradius", Confidence: "low"},
		1900:  {Name: "ssdp", CPE: "cpe:/a:upnp:upnp", Confidence: "medium"},
		2049:  {Name: "nfs", CPE: "cpe:/a:nfs:nfs", Confidence: "medium"},
		2375:  {Name: "docker", CPE: "cpe:/a:docker:docker", Confidence: "medium"},
		2376:  {Name: "docker-tls", CPE: "cpe:/a:docker:docker", Confidence: "medium"},
		2379:  {Name: "etcd", CPE: "cpe:/a:etcd:etcd", Confidence: "medium"},
		3000:  {Name: "http-alt", CPE: "cpe:/a:http:http_server", Confidence: "low"},
		3306:  {Name: "mysql", CPE: "cpe:/a:mysql:mysql", Confidence: "medium"},
		3389:  {Name: "rdp", CPE: "cpe:/o:microsoft:windows", Confidence: "medium"},
		4500:  {Name: "ipsec-nat-t", CPE: "cpe:/a:ipsec:ipsec", Confidence: "medium"},
		5000:  {Name: "docker-registry", CPE: "cpe:/a:docker:distribution", Confidence: "medium"},
		5001:  {Name: "docker-registry", CPE: "cpe:/a:docker:distribution", Confidence: "medium"},
		5060:  {Name: "sip", CPE: "cpe:/a:sip:sip", Confidence: "medium"},
		5353:  {Name: "mdns", CPE: "cpe:/a:multicast_dns:mdns", Confidence: "medium"},
		5432:  {Name: "postgresql", CPE: "cpe:/a:postgresql:postgresql", Confidence: "medium"},
		5601:  {Name: "kibana", CPE: "cpe:/a:elastic:kibana", Confidence: "medium"},
		5900:  {Name: "vnc", CPE: "cpe:/a:realvnc:vnc", Confidence: "medium"},
		5985:  {Name: "winrm", CPE: "cpe:/o:microsoft:windows", Confidence: "medium"},
		5986:  {Name: "winrm-tls", CPE: "cpe:/o:microsoft:windows", Confidence: "medium"},
		6379:  {Name: "redis", CPE: "cpe:/a:redis:redis", Confidence: "medium"},
		6443:  {Name: "kubernetes-api", CPE: "cpe:/a:kubernetes:kubernetes", Confidence: "medium"},
		8000:  {Name: "http-alt", CPE: "cpe:/a:http:http_server", Confidence: "low"},
		8080:  {Name: "http-proxy", CPE: "cpe:/a:http:http_server", Confidence: "low"},
		8443:  {Name: "https-alt", CPE: "cpe:/a:http:http_server", Confidence: "low"},
		8888:  {Name: "http-alt", CPE: "cpe:/a:http:http_server", Confidence: "low"},
		9200:  {Name: "elasticsearch", CPE: "cpe:/a:elastic:elasticsearch", Confidence: "medium"},
		9300:  {Name: "elasticsearch-transport", CPE: "cpe:/a:elastic:elasticsearch", Confidence: "medium"},
		10250: {Name: "kubelet", CPE: "cpe:/a:kubernetes:kubernetes", Confidence: "medium"},
		10255: {Name: "kubelet", CPE: "cpe:/a:kubernetes:kubernetes", Confidence: "medium"},
		11211: {Name: "memcached", CPE: "cpe:/a:memcached:memcached", Confidence: "medium"},
		27017: {Name: "mongodb", CPE: "cpe:/a:mongodb:mongodb", Confidence: "medium"},
	}
	fp := table[port]
	if fp.Evidence == "" && fp.Name != "" {
		fp.Evidence = fmt.Sprintf("port=%d/%s", port, protocol)
	}
	return fp
}

func refineFromEvidence(fp serviceID, evidence string) serviceID {
	lower := strings.ToLower(evidence)
	switch {
	case strings.Contains(lower, "openssh"):
		fp.Name, fp.Product, fp.CPE, fp.Confidence = "ssh", "OpenSSH", "cpe:/a:openssh:openssh", "high"
		fp.Version = versionAfter(lower, "openssh_")
	case strings.Contains(lower, "dropbear"):
		fp.Name, fp.Product, fp.CPE, fp.Confidence = "ssh", "Dropbear SSH", "cpe:/a:dropbear_ssh_project:dropbear_ssh", "high"
		fp.Version = versionAfter(lower, "dropbear_")
	case strings.Contains(lower, "apache"):
		fp.Name, fp.Product, fp.CPE, fp.Confidence = "http", "Apache HTTP Server", "cpe:/a:apache:http_server", "high"
		fp.Version = versionAfter(lower, "apache/")
	case strings.Contains(lower, "nginx"):
		fp.Name, fp.Product, fp.CPE, fp.Confidence = "http", "nginx", "cpe:/a:nginx:nginx", "high"
		fp.Version = versionAfter(lower, "nginx/")
	case strings.Contains(lower, "microsoft-iis"):
		fp.Name, fp.Product, fp.CPE, fp.Confidence = "http", "Microsoft IIS", "cpe:/a:microsoft:iis", "high"
		fp.Version = versionAfter(lower, "microsoft-iis/")
	case strings.Contains(lower, "postfix"):
		fp.Name, fp.Product, fp.CPE, fp.Confidence = "smtp", "Postfix", "cpe:/a:postfix:postfix", "high"
	case strings.Contains(lower, "mysql"):
		fp.Name, fp.Product, fp.CPE, fp.Confidence = "mysql", "MySQL", "cpe:/a:mysql:mysql", "high"
	case strings.Contains(lower, "postgresql"):
		fp.Name, fp.Product, fp.CPE, fp.Confidence = "postgresql", "PostgreSQL", "cpe:/a:postgresql:postgresql", "high"
	case strings.Contains(lower, "redis"):
		fp.Name, fp.Product, fp.CPE, fp.Confidence = "redis", "Redis", "cpe:/a:redis:redis", "high"
	case strings.Contains(lower, "mongodb"):
		fp.Name, fp.Product, fp.CPE, fp.Confidence = "mongodb", "MongoDB", "cpe:/a:mongodb:mongodb", "high"
	case strings.Contains(lower, "elasticsearch"):
		fp.Name, fp.Product, fp.CPE, fp.Confidence = "elasticsearch", "Elasticsearch", "cpe:/a:elastic:elasticsearch", "high"
	case strings.Contains(lower, "kubernetes"):
		fp.Name, fp.Product, fp.CPE, fp.Confidence = "kubernetes-api", "Kubernetes", "cpe:/a:kubernetes:kubernetes", "high"
	case strings.Contains(lower, "smb"):
		fp.Name, fp.Product, fp.CPE, fp.Confidence = "smb", "SMB", "cpe:/o:microsoft:windows", "medium"
	}
	if fp.Evidence == "" {
		fp.Evidence = evidence
	} else {
		fp.Evidence += " | " + evidence
	}
	if fp.Confidence == "" {
		fp.Confidence = "low"
	}
	return fp
}

func activeProbe(ctx context.Context, address string, port int, protocol string) serviceID {
	if protocol != "tcp" {
		return serviceID{}
	}
	switch port {
	case 22, 21, 25, 110, 143:
		return lineProbe(ctx, address, port)
	case 80, 8000, 8080, 8081, 8888:
		return httpProbe(ctx, "http://"+address)
	case 443, 8443, 6443:
		return httpProbe(ctx, "https://"+address)
	case 6379:
		return redisProbe(ctx, address)
	case 9200:
		return httpProbe(ctx, "http://"+address)
	case 2375:
		return httpProbe(ctx, "http://"+address+"/version")
	case 2376:
		return httpProbe(ctx, "https://"+address+"/version")
	default:
		return serviceID{}
	}
}

func lineProbe(ctx context.Context, address string, port int) serviceID {
	conn, err := (&net.Dialer{Timeout: 1200 * time.Millisecond}).DialContext(ctx, "tcp", address)
	if err != nil {
		return serviceID{}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))
	switch port {
	case 25:
		_, _ = conn.Write([]byte("EHLO enumscan.local\r\n"))
	case 21, 110, 143:
		_, _ = conn.Write([]byte("\r\n"))
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || strings.TrimSpace(line) == "" {
		return serviceID{}
	}
	return refineFromEvidence(fingerprintFromPort(port, "tcp"), line)
}

func redisProbe(ctx context.Context, address string) serviceID {
	conn, err := (&net.Dialer{Timeout: 1200 * time.Millisecond}).DialContext(ctx, "tcp", address)
	if err != nil {
		return serviceID{}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1200 * time.Millisecond))
	_, _ = conn.Write([]byte("*1\r\n$4\r\nPING\r\n"))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return serviceID{}
	}
	return refineFromEvidence(fingerprintFromPort(6379, "tcp"), string(buf[:n]))
}

func httpProbe(ctx context.Context, url string) serviceID {
	client := &http.Client{
		Timeout:   1500 * time.Millisecond,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return serviceID{}
	}
	resp, err := client.Do(req)
	if err != nil {
		return serviceID{}
	}
	defer resp.Body.Close()
	var evidence bytes.Buffer
	evidence.WriteString("status=" + resp.Status)
	for _, header := range []string{"Server", "X-Powered-By", "X-Elastic-Product", "Docker-Experimental"} {
		if value := resp.Header.Get(header); value != "" {
			evidence.WriteString(";" + header + "=" + value)
		}
	}
	port := 80
	if strings.HasPrefix(url, "https://") {
		port = 443
	}
	if strings.Contains(url, ":6443") {
		port = 6443
	}
	return refineFromEvidence(fingerprintFromPort(port, "tcp"), evidence.String())
}

func mergeFingerprint(base, active serviceID) serviceID {
	if active.Name != "" {
		base.Name = active.Name
	}
	if active.Version != "" {
		base.Version = active.Version
	}
	if active.Product != "" {
		base.Product = active.Product
	}
	if active.CPE != "" {
		base.CPE = active.CPE
	}
	if active.Confidence != "" {
		base.Confidence = active.Confidence
	}
	if active.Evidence != "" {
		if base.Evidence == "" {
			base.Evidence = active.Evidence
		} else {
			base.Evidence += " | " + active.Evidence
		}
	}
	return base
}

func serviceMetadata(fp serviceID, port int, protocol string) string {
	parts := []string{
		"port=" + strconv.Itoa(port),
		"protocol=" + protocol,
		"confidence=" + firstNonEmpty(fp.Confidence, "low"),
	}
	if fp.Product != "" {
		parts = append(parts, "product="+cleanEvidence(fp.Product))
	}
	if fp.Evidence != "" {
		parts = append(parts, "evidence="+cleanEvidence(fp.Evidence))
	}
	return strings.Join(parts, ";")
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func versionAfter(value, marker string) string {
	idx := strings.Index(value, marker)
	if idx < 0 {
		return ""
	}
	rest := value[idx+len(marker):]
	end := 0
	for end < len(rest) {
		ch := rest[end]
		if (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-' || ch == 'p' {
			end++
			continue
		}
		break
	}
	return strings.Trim(rest[:end], "_-")
}

func cleanEvidence(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	value = strings.ReplaceAll(value, ";", ",")
	value = strings.TrimSpace(value)
	if len(value) > 220 {
		return value[:220]
	}
	return value
}
