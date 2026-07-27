package modules

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
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

const (
	EventSpecializedDiscovered = "specialized.discovered"
)

type Specialized struct {
	db    *store.SQLiteCLI
	guard scope.Guard
	cfg   models.SpecializedConfig
}

func NewSpecialized(db *store.SQLiteCLI, guard scope.Guard, cfg models.SpecializedConfig) Specialized {
	return Specialized{db: db, guard: guard, cfg: cfg}
}

func (s Specialized) Name() string { return "specialized" }

func (s Specialized) Subscriptions() []string {
	return []string{EventTarget, EventHost, EventPort, EventService, EventHTTPURL}
}

func (s Specialized) Handle(ctx context.Context, event models.Event) ([]models.Event, error) {
	var results []models.Event

	switch event.Type {
	case EventTarget, EventHost:
		if s.cfg.EnableCloud {
			newEvts := s.probeCloudTarget(ctx, event)
			results = append(results, newEvts...)
		}
	case EventHTTPURL:
		if s.cfg.EnableCloud {
			newEvts := s.probeCloudURL(ctx, event)
			results = append(results, newEvts...)
		}
	case EventPort, EventService:
		host, portStr, err := net.SplitHostPort(event.Target)
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
		serviceName := event.Data["service"]
		protocol := firstNonEmpty(event.Data["protocol"], "tcp")

		if s.cfg.EnableSMB && (port == 445 || port == 139 || serviceName == "smb" || serviceName == "netbios-ssn") {
			newEvts := s.probeSMB(ctx, event, host, port)
			results = append(results, newEvts...)
		}
		if s.cfg.EnableLDAP && (port == 389 || port == 636 || port == 3268 || port == 3269 || serviceName == "ldap" || serviceName == "ldaps") {
			newEvts := s.probeLDAP(ctx, event, host, port)
			results = append(results, newEvts...)
		}
		if s.cfg.EnableSNMP && (port == 161 || protocol == "udp" || serviceName == "snmp") {
			newEvts := s.probeSNMP(ctx, event, host, port)
			results = append(results, newEvts...)
		}
		if s.cfg.EnableContainer && isContainerPort(port, serviceName) {
			newEvts := s.probeContainer(ctx, event, host, port)
			results = append(results, newEvts...)
		}
		if s.cfg.EnableDatabase && isDatabasePort(port, serviceName) {
			newEvts := s.probeDatabase(ctx, event, host, port)
			results = append(results, newEvts...)
		}
	}

	return results, nil
}

// -----------------------------------------------------------------------------
// 1. SMB Enumeration
// -----------------------------------------------------------------------------

func (s Specialized) probeSMB(ctx context.Context, event models.Event, host string, port int) []models.Event {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// SMB2 Negotiate Protocol Request PDU (Header + Negotiate Req)
	smb2Header := []byte{
		0x00, 0x00, 0x00, 0x44, // NetBIOS header length (68 bytes)
		0xfe, 'S', 'M', 'B', // Protocol ID \xfeSMB
		0x40, 0x00, // Header length (64)
		0x00, 0x00, // Credit charge
		0x00, 0x00, // Status
		0x00, 0x00, // Command (0x00 = Negotiate)
		0x00, 0x00, // Credits
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // Next command
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID
		0x00, 0x00, 0x00, 0x00, // Process ID
		0x00, 0x00, 0x00, 0x00, // Tree ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		// Negotiate Context
		0x24, 0x00, // Struct size
		0x02, 0x00, // Dialect count (2)
		0x01, 0x00, // Security mode (signing enabled)
		0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Client GUID
		0x00, 0x00, 0x00, 0x00, // Negotiate context offset
		0x00, 0x00, // Negotiate context count
		0x00, 0x00, // Reserved
		0x02, 0x02, // Dialect SMB 2.0.2
		0x10, 0x02, // Dialect SMB 2.1
	}

	if _, err := conn.Write(smb2Header); err != nil {
		return nil
	}

	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil || n < 8 {
		return nil
	}

	dialect := "SMB2/SMB3"
	security := "Signing Enabled"
	if bytes.Contains(resp[:n], []byte("\xfeSMB")) || bytes.Contains(resp[:n], []byte("\xffSMB")) {
		metadata := fmt.Sprintf("address=%s;dialect=%s;security=%s;response_bytes=%d", address, dialect, security, n)
		_ = s.db.AddAsset(ctx, models.Asset{
			ScanID:   event.ScanID,
			Type:     "smb_service",
			Value:    address,
			Parent:   event.Target,
			Metadata: metadata,
		})

		_ = s.db.AddFinding(ctx, models.Finding{
			ScanID:      event.ScanID,
			Severity:    "medium",
			Confidence:  "high",
			Asset:       address,
			Title:       "Exposed SMB Service",
			Evidence:    metadata,
			Remediation: "Ensure SMB service is restricted behind firewall and SMBv1 is disabled.",
		})

		return []models.Event{{
			ScanID: event.ScanID,
			Type:   EventSpecializedDiscovered,
			Target: address,
			Data:   map[string]string{"category": "smb", "dialect": dialect},
		}}
	}

	return nil
}

// -----------------------------------------------------------------------------
// 2. LDAP & Active Directory Enumeration
// -----------------------------------------------------------------------------

func (s Specialized) probeLDAP(ctx context.Context, event models.Event, host string, port int) []models.Event {
	address := fmt.Sprintf("%s:%d", host, port)
	useTLS := (port == 636 || port == 3269)

	var conn net.Conn
	var err error
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	if useTLS {
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{InsecureSkipVerify: true})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// BER encoded LDAP SearchRequest for RootDSE (base="", scope=0, filter=(objectClass=*), attributes=["namingContexts", "defaultNamingContext", "dnsHostName"])
	ldapRootDSERequest := []byte{
		0x30, 0x25, // Sequence (37 bytes)
		0x02, 0x01, 0x01, // Message ID: 1
		0x63, 0x20, // SearchRequest (32 bytes)
		0x04, 0x00, // BaseDN: ""
		0x0a, 0x01, 0x00, // Scope: baseObject (0)
		0x0a, 0x01, 0x00, // DerefAliases: neverDerefAliases (0)
		0x02, 0x01, 0x00, // SizeLimit: 0
		0x02, 0x01, 0x00, // TimeLimit: 0
		0x01, 0x01, 0x00, // TypesOnly: false
		0xa3, 0x07, // Filter: present (objectClass)
		0x04, 0x0b, 'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
		0x30, 0x07, // Attributes
		0x04, 0x05, 'n', 'a', 'm', 'i', 'n', 'g',
	}

	if _, err := conn.Write(ldapRootDSERequest); err != nil {
		return nil
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return nil
	}

	raw := string(buf[:n])
	isAD := strings.Contains(strings.ToLower(raw), "dc=") || strings.Contains(raw, "namingContexts") || port == 3268 || port == 3269

	metadata := fmt.Sprintf("address=%s;is_active_directory=%t;response_len=%d", address, isAD, n)
	_ = s.db.AddAsset(ctx, models.Asset{
		ScanID:   event.ScanID,
		Type:     "ldap_service",
		Value:    address,
		Parent:   event.Target,
		Metadata: metadata,
	})

	if isAD {
		_ = s.db.AddAsset(ctx, models.Asset{
			ScanID:   event.ScanID,
			Type:     "active_directory_domain",
			Value:    host,
			Parent:   address,
			Metadata: "source=ldap_rootdse_probe",
		})
	}

	_ = s.db.AddFinding(ctx, models.Finding{
		ScanID:      event.ScanID,
		Severity:    "medium",
		Confidence:  "medium",
		Asset:       address,
		Title:       "Anonymous LDAP RootDSE Access Allowed",
		Evidence:    metadata,
		Remediation: "Restrict LDAP anonymous binds and enforce LDAP signing & channel binding.",
	})

	return []models.Event{{
		ScanID: event.ScanID,
		Type:   EventSpecializedDiscovered,
		Target: address,
		Data:   map[string]string{"category": "ldap", "active_directory": strconv.FormatBool(isAD)},
	}}
}

// -----------------------------------------------------------------------------
// 3. SNMP MIB Walking
// -----------------------------------------------------------------------------

func (s Specialized) probeSNMP(ctx context.Context, event models.Event, host string, port int) []models.Event {
	if port == 0 {
		port = 161
	}
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("udp", address, 1500*time.Millisecond)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))

	communities := s.cfg.SNMPCommunities
	if len(communities) == 0 {
		communities = []string{"public", "private", "community"}
	}

	var events []models.Event
	for _, comm := range communities {
		// SNMPv2c GetNext PDU for OID 1.3.6.1.2.1.1 (sysDescr)
		pdu := buildSNMPGetNextPDU(comm, []int{1, 3, 6, 1, 2, 1, 1, 1, 0})
		if _, err := conn.Write(pdu); err != nil {
			continue
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err == nil && n > 10 {
			evidence := fmt.Sprintf("community=%s;response_bytes=%d", comm, n)
			_ = s.db.AddAsset(ctx, models.Asset{
				ScanID:   event.ScanID,
				Type:     "snmp_agent",
				Value:    address,
				Parent:   event.Target,
				Metadata: evidence,
			})

			_ = s.db.AddFinding(ctx, models.Finding{
				ScanID:      event.ScanID,
				Severity:    "high",
				Confidence:  "high",
				Asset:       address,
				Title:       "Default SNMP Community String Accepted",
				Evidence:    evidence,
				Remediation: "Change default SNMP community strings and restrict UDP 161 access.",
			})

			events = append(events, models.Event{
				ScanID: event.ScanID,
				Type:   EventSpecializedDiscovered,
				Target: address,
				Data:   map[string]string{"category": "snmp", "community": comm},
			})
			break
		}
	}
	return events
}

func buildSNMPGetNextPDU(community string, oid []int) []byte {
	commBytes := []byte(community)
	oidBytes := encodeOID(oid)

	// Varbind
	varbind := append([]byte{0x30, byte(len(oidBytes) + 2)}, oidBytes...)
	varbind = append(varbind, 0x05, 0x00) // Null value

	// Varbind list
	varbindList := append([]byte{0x30, byte(len(varbind))}, varbind...)

	// GetNextRequest PDU (0xa1)
	pduHeader := []byte{0xa1, byte(len(varbindList) + 12), 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00}
	pdu := append(pduHeader, varbindList...)

	// Version (v2c = 1)
	ver := []byte{0x02, 0x01, 0x01}
	comm := append([]byte{0x04, byte(len(commBytes))}, commBytes...)

	seqBody := append(ver, comm...)
	seqBody = append(seqBody, pdu...)

	return append([]byte{0x30, byte(len(seqBody))}, seqBody...)
}

func encodeOID(oid []int) []byte {
	if len(oid) < 2 {
		return []byte{0x06, 0x01, 0x00}
	}
	enc := []byte{byte(oid[0]*40 + oid[1])}
	for _, val := range oid[2:] {
		if val < 128 {
			enc = append(enc, byte(val))
		} else {
			enc = append(enc, byte((val>>7)|0x80), byte(val&0x7f))
		}
	}
	return append([]byte{0x06, byte(len(enc))}, enc...)
}

// -----------------------------------------------------------------------------
// 4. Cloud Asset Checks (AWS, Azure, GCP, DigitalOcean, Cloudflare)
// -----------------------------------------------------------------------------

func (s Specialized) probeCloudTarget(ctx context.Context, event models.Event) []models.Event {
	target := event.Target
	if target == "" {
		return nil
	}

	var results []models.Event
	vendor, details := detectCloudVendor(target)
	if vendor != "" {
		metadata := fmt.Sprintf("vendor=%s;details=%s", vendor, details)
		_ = s.db.AddAsset(ctx, models.Asset{
			ScanID:   event.ScanID,
			Type:     "cloud_asset",
			Value:    target,
			Parent:   event.Target,
			Metadata: metadata,
		})
		results = append(results, models.Event{
			ScanID: event.ScanID,
			Type:   EventSpecializedDiscovered,
			Target: target,
			Data:   map[string]string{"category": "cloud", "vendor": vendor, "details": details},
		})
	}

	// Check storage bucket exposure based on target name
	cleanName := sanitizeBucketName(target)
	if cleanName != "" {
		bucketURLs := []struct {
			vendor string
			url    string
		}{
			{"aws", fmt.Sprintf("https://%s.s3.amazonaws.com", cleanName)},
			{"azure", fmt.Sprintf("https://%s.blob.core.windows.net", cleanName)},
			{"gcp", fmt.Sprintf("https://storage.googleapis.com/%s", cleanName)},
			{"digitalocean", fmt.Sprintf("https://%s.digitaloceanspaces.com", cleanName)},
		}

		client := &http.Client{Timeout: 2 * time.Second}
		for _, b := range bucketURLs {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.url, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			_ = resp.Body.Close()

			if resp.StatusCode == 200 || resp.StatusCode == 403 {
				metadata := fmt.Sprintf("vendor=%s;url=%s;status=%d", b.vendor, b.url, resp.StatusCode)
				_ = s.db.AddAsset(ctx, models.Asset{
					ScanID:   event.ScanID,
					Type:     "cloud_storage_bucket",
					Value:    b.url,
					Parent:   target,
					Metadata: metadata,
				})

				if resp.StatusCode == 200 {
					_ = s.db.AddFinding(ctx, models.Finding{
						ScanID:      event.ScanID,
						Severity:    "high",
						Confidence:  "high",
						Asset:       b.url,
						Title:       "Publicly Accessible Cloud Storage Bucket",
						Evidence:    metadata,
						Remediation: "Enforce strict IAM policies and block public access to storage bucket.",
					})
				}
			}
		}
	}

	return results
}

func (s Specialized) probeCloudURL(ctx context.Context, event models.Event) []models.Event {
	url := event.Target
	if url == "" {
		return nil
	}

	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	_ = resp.Body.Close()

	vendor := ""
	details := ""
	server := strings.ToLower(resp.Header.Get("Server"))
	via := strings.ToLower(resp.Header.Get("Via"))

	switch {
	case strings.Contains(server, "cloudflare") || resp.Header.Get("CF-Ray") != "":
		vendor, details = "cloudflare", "Cloudflare CDN / Proxy"
	case strings.Contains(server, "amazons3") || strings.Contains(via, "cloudfront") || resp.Header.Get("X-Amz-Cf-Id") != "":
		vendor, details = "aws", "Amazon Web Services (CloudFront / S3)"
	case strings.Contains(server, "microsoft-iis") || resp.Header.Get("X-Ms-Ref") != "":
		vendor, details = "azure", "Microsoft Azure (FrontDoor / AppService)"
	case strings.Contains(server, "gws") || strings.Contains(server, "google") || resp.Header.Get("X-Cloud-Trace-Context") != "":
		vendor, details = "gcp", "Google Cloud Platform"
	}

	if vendor != "" {
		metadata := fmt.Sprintf("vendor=%s;details=%s;url=%s", vendor, details, url)
		_ = s.db.AddAsset(ctx, models.Asset{
			ScanID:   event.ScanID,
			Type:     "cloud_infrastructure",
			Value:    url,
			Parent:   event.Target,
			Metadata: metadata,
		})
		return []models.Event{{
			ScanID: event.ScanID,
			Type:   EventSpecializedDiscovered,
			Target: url,
			Data:   map[string]string{"category": "cloud", "vendor": vendor, "details": details},
		}}
	}

	return nil
}

func detectCloudVendor(target string) (string, string) {
	lower := strings.ToLower(target)
	switch {
	case strings.Contains(lower, "amazonaws.com") || strings.Contains(lower, "cloudfront.net"):
		return "aws", "Amazon Web Services Host"
	case strings.Contains(lower, "azure.com") || strings.Contains(lower, "azurewebsites.net") || strings.Contains(lower, "cloudapp.azure.com"):
		return "azure", "Microsoft Azure Host"
	case strings.Contains(lower, "googleapis.com") || strings.Contains(lower, "appspot.com") || strings.Contains(lower, "googleusercontent.com"):
		return "gcp", "Google Cloud Host"
	case strings.Contains(lower, "digitaloceanspaces.com") || strings.Contains(lower, "digitalocean.com"):
		return "digitalocean", "DigitalOcean Host"
	case strings.Contains(lower, "cloudflare.com") || strings.Contains(lower, "workers.dev"):
		return "cloudflare", "Cloudflare Host"
	}
	return "", ""
}

func sanitizeBucketName(target string) string {
	parts := strings.Split(target, ".")
	if len(parts) == 0 {
		return ""
	}
	name := parts[0]
	if name == "www" && len(parts) > 1 {
		name = parts[1]
	}
	name = strings.ToLower(name)
	if len(name) < 3 || len(name) > 63 {
		return ""
	}
	return name
}

// -----------------------------------------------------------------------------
// 5. Container & Kubernetes Exposure Checks
// -----------------------------------------------------------------------------

func isContainerPort(port int, service string) bool {
	return port == 2375 || port == 2376 || port == 5000 || port == 5001 || port == 6443 || port == 10250 || port == 10255 || port == 2379 ||
		service == "docker" || service == "docker-tls" || service == "docker-registry" || service == "kubernetes-api" || service == "kubelet" || service == "etcd"
}

func (s Specialized) probeContainer(ctx context.Context, event models.Event, host string, port int) []models.Event {
	address := fmt.Sprintf("%s:%d", host, port)
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}

	scheme := "http"
	if port == 2376 || port == 5001 || port == 6443 || port == 10250 {
		scheme = "https"
	}

	checks := containerChecks(port, event.Data["service"])
	var events []models.Event
	for _, check := range checks {
		path := check.path
		targetURL := fmt.Sprintf("%s://%s%s", scheme, address, path)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			continue
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		_ = resp.Body.Close()

		if !check.accepts(resp.StatusCode) || (len(bodyBytes) == 0 && check.kind != "registry") {
			continue
		}
		if check.kind == "compose" && !isComposeDocument(bodyBytes) {
			continue
		}
		category, title := containerCategory(port, event.Data["service"], check.kind)
		metadata := fmt.Sprintf("address=%s;category=%s;path=%s;status=%d;body_preview=%s", address, category, path, resp.StatusCode, cleanEvidence(string(bodyBytes)))
		assetType := "container_exposure"
		switch check.kind {
		case "docker_socket":
			assetType = "docker_socket"
		case "registry":
			assetType = "docker_registry"
		case "runtime":
			assetType = "container_runtime"
		case "compose":
			assetType = "docker_compose_file"
		case "kubernetes_secrets":
			assetType = "kubernetes_secrets_endpoint"
			metadata += ";items=" + strconv.Itoa(kubernetesItemCount(bodyBytes))
		}
		_ = s.db.AddAsset(ctx, models.Asset{
			ScanID:   event.ScanID,
			Type:     assetType,
			Value:    targetURL,
			Parent:   event.Target,
			Metadata: metadata,
		})

		severity := "high"
		if check.kind == "runtime" || check.kind == "registry" {
			severity = "medium"
		}
		_ = s.db.AddFinding(ctx, models.Finding{
			ScanID:      event.ScanID,
			Severity:    severity,
			Confidence:  "high",
			Asset:       targetURL,
			Title:       title,
			Evidence:    metadata,
			Remediation: "Enable TLS authentication and restrict access to control plane management ports.",
		})

		events = append(events, models.Event{
			ScanID: event.ScanID,
			Type:   EventSpecializedDiscovered,
			Target: targetURL,
			Data:   map[string]string{"category": category, "path": path, "kind": check.kind},
		})
	}

	return events
}

type containerCheck struct {
	path string
	kind string
}

func (c containerCheck) accepts(status int) bool {
	// Registries deliberately return 401 when authentication is correctly
	// required. That response still establishes the registry's presence.
	return status == http.StatusOK || (c.kind == "registry" && status == http.StatusUnauthorized)
}

func containerChecks(port int, service string) []containerCheck {
	service = strings.ToLower(service)
	checks := []containerCheck{}
	if port == 2375 || port == 2376 || service == "docker" || service == "docker-tls" {
		checks = append(checks,
			containerCheck{"/version", "docker_socket"},
			containerCheck{"/info", "runtime"},
			containerCheck{"/containers/json", "runtime"},
			containerCheck{"/docker-compose.yml", "compose"},
			containerCheck{"/docker-compose.yaml", "compose"},
			containerCheck{"/compose.yaml", "compose"},
		)
	}
	if port == 5000 || port == 5001 || service == "docker-registry" {
		checks = append(checks, containerCheck{"/v2/", "registry"}, containerCheck{"/v2/_catalog", "registry"})
	}
	if port == 6443 || port == 10250 || port == 10255 || service == "kubernetes-api" || service == "kubelet" {
		checks = append(checks,
			containerCheck{"/version", "runtime"},
			containerCheck{"/api/v1", "runtime"},
			containerCheck{"/api/v1/secrets", "kubernetes_secrets"},
			containerCheck{"/api/v1/namespaces/default/secrets", "kubernetes_secrets"},
		)
	}
	if port == 2379 || service == "etcd" {
		checks = append(checks, containerCheck{"/v2/keys", "runtime"})
	}
	return checks
}

func containerCategory(port int, service, kind string) (string, string) {
	switch kind {
	case "docker_socket":
		return "docker", "Unauthenticated Docker API Socket Exposed"
	case "registry":
		return "docker_registry", "Docker Registry Discovered"
	case "compose":
		return "docker_compose", "Docker Compose File Exposed"
	case "kubernetes_secrets":
		return "kubernetes", "Kubernetes Secrets Endpoint Exposed"
	}
	switch {
	case port == 6443:
		return "kubernetes", "Unauthenticated Kubernetes API Exposed"
	case port == 10250 || port == 10255:
		return "kubelet", "Unauthenticated Kubelet API Exposed"
	case port == 2379:
		return "etcd", "Unauthenticated Etcd Key-Value Store Exposed"
	default:
		return "container", "Container Runtime Endpoint Exposed"
	}
}

func kubernetesItemCount(body []byte) int {
	var response struct {
		Items []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(body, &response) != nil {
		return 0
	}
	return len(response.Items)
}

func isComposeDocument(body []byte) bool {
	lower := strings.ToLower(string(body))
	return strings.Contains(lower, "services:") &&
		(strings.Contains(lower, "version:") || strings.Contains(lower, "image:") || strings.Contains(lower, "build:"))
}

// -----------------------------------------------------------------------------
// 6. Database Exposure & Authentication Checks
// -----------------------------------------------------------------------------

func isDatabasePort(port int, service string) bool {
	dbPorts := map[int]bool{
		3306:  true, // MySQL
		5432:  true, // PostgreSQL
		1433:  true, // MSSQL
		6379:  true, // Redis
		9200:  true, // Elasticsearch
		27017: true, // MongoDB
		11211: true, // Memcached
		5984:  true, // CouchDB
	}
	if dbPorts[port] {
		return true
	}
	dbServices := map[string]bool{
		"mysql": true, "postgresql": true, "mssql": true, "redis": true,
		"elasticsearch": true, "mongodb": true, "memcached": true, "couchdb": true,
	}
	return dbServices[service]
}

func (s Specialized) probeDatabase(ctx context.Context, event models.Event, host string, port int) []models.Event {
	address := fmt.Sprintf("%s:%d", host, port)
	serviceName := event.Data["service"]

	switch {
	case port == 6379 || serviceName == "redis":
		return s.checkRedis(ctx, event, address)
	case port == 9200 || serviceName == "elasticsearch":
		return s.checkElasticsearch(ctx, event, address)
	case port == 11211 || serviceName == "memcached":
		return s.checkMemcached(ctx, event, address)
	case port == 27017 || serviceName == "mongodb":
		return s.checkMongoDB(ctx, event, address)
	case port == 3306 || serviceName == "mysql":
		return s.checkMySQL(ctx, event, address)
	case port == 5432 || serviceName == "postgresql":
		return s.checkPostgreSQL(ctx, event, address)
	case port == 1433 || serviceName == "mssql":
		return s.checkMSSQL(ctx, event, address)
	default:
		return s.checkGenericDB(ctx, event, address, port)
	}
}

func (s Specialized) checkRedis(ctx context.Context, event models.Event, address string) []models.Event {
	conn, err := (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))

	_, _ = conn.Write([]byte("INFO\r\n"))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil
	}

	resp := string(buf[:n])
	if strings.Contains(resp, "redis_version") || strings.Contains(resp, "# Server") {
		metadata := fmt.Sprintf("address=%s;db=redis;auth_required=false;preview=%s", address, cleanEvidence(resp))
		_ = s.db.AddAsset(ctx, models.Asset{
			ScanID:   event.ScanID,
			Type:     "database_instance",
			Value:    address,
			Parent:   event.Target,
			Metadata: metadata,
		})
		_ = s.db.AddFinding(ctx, models.Finding{
			ScanID:      event.ScanID,
			Severity:    "high",
			Confidence:  "high",
			Asset:       address,
			Title:       "Unauthenticated Redis Database Exposed",
			Evidence:    metadata,
			Remediation: "Require password authentication in redis.conf and bind Redis to local interfaces.",
		})
		return []models.Event{{
			ScanID: event.ScanID,
			Type:   EventSpecializedDiscovered,
			Target: address,
			Data:   map[string]string{"category": "database", "vendor": "redis", "unauthenticated": "true"},
		}}
	}
	return nil
}

func (s Specialized) checkElasticsearch(ctx context.Context, event models.Event, address string) []models.Event {
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/", nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	bodyStr := string(bodyBytes)
	if resp.StatusCode == 200 && (strings.Contains(bodyStr, "youknow,forsearch") || strings.Contains(bodyStr, "cluster_name")) {
		metadata := fmt.Sprintf("address=%s;db=elasticsearch;auth_required=false;preview=%s", address, cleanEvidence(bodyStr))
		_ = s.db.AddAsset(ctx, models.Asset{
			ScanID:   event.ScanID,
			Type:     "database_instance",
			Value:    address,
			Parent:   event.Target,
			Metadata: metadata,
		})
		_ = s.db.AddFinding(ctx, models.Finding{
			ScanID:      event.ScanID,
			Severity:    "high",
			Confidence:  "high",
			Asset:       address,
			Title:       "Unauthenticated Elasticsearch Instance Exposed",
			Evidence:    metadata,
			Remediation: "Enable Elastic Security (X-Pack) authentication and restrict network access to port 9200.",
		})
		return []models.Event{{
			ScanID: event.ScanID,
			Type:   EventSpecializedDiscovered,
			Target: address,
			Data:   map[string]string{"category": "database", "vendor": "elasticsearch", "unauthenticated": "true"},
		}}
	}
	return nil
}

func (s Specialized) checkMemcached(ctx context.Context, event models.Event, address string) []models.Event {
	conn, err := (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))

	_, _ = conn.Write([]byte("stats\r\n"))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil
	}

	resp := string(buf[:n])
	if strings.Contains(resp, "STAT version") || strings.Contains(resp, "STAT pid") {
		metadata := fmt.Sprintf("address=%s;db=memcached;auth_required=false;preview=%s", address, cleanEvidence(resp))
		_ = s.db.AddAsset(ctx, models.Asset{
			ScanID:   event.ScanID,
			Type:     "database_instance",
			Value:    address,
			Parent:   event.Target,
			Metadata: metadata,
		})
		_ = s.db.AddFinding(ctx, models.Finding{
			ScanID:      event.ScanID,
			Severity:    "high",
			Confidence:  "high",
			Asset:       address,
			Title:       "Unauthenticated Memcached Service Exposed",
			Evidence:    metadata,
			Remediation: "Bind Memcached to localhost or use SASL authentication.",
		})
		return []models.Event{{
			ScanID: event.ScanID,
			Type:   EventSpecializedDiscovered,
			Target: address,
			Data:   map[string]string{"category": "database", "vendor": "memcached", "unauthenticated": "true"},
		}}
	}
	return nil
}

func (s Specialized) checkMongoDB(ctx context.Context, event models.Event, address string) []models.Event {
	conn, err := (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))

	// Wire protocol OP_QUERY message for isMaster command
	opQuery := []byte{
		0x3a, 0x00, 0x00, 0x00, // Message length (58)
		0x01, 0x00, 0x00, 0x00, // Request ID
		0x00, 0x00, 0x00, 0x00, // Response to
		0xd4, 0x07, 0x00, 0x00, // OpCode (2004 OP_QUERY)
		0x00, 0x00, 0x00, 0x00, // Flags
		'a', 'd', 'm', 'i', 'n', '.', '$', 'c', 'm', 'd', 0x00, // Collection name
		0x00, 0x00, 0x00, 0x00, // Number to skip
		0xff, 0xff, 0xff, 0xff, // Number to return (-1)
		// BSON document { "isMaster": 1 }
		0x13, 0x00, 0x00, 0x00, // Document size (19)
		0x10, 'i', 's', 'M', 'a', 's', 't', 'e', 'r', 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	}

	if _, err := conn.Write(opQuery); err != nil {
		return nil
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err == nil && n > 16 {
		metadata := fmt.Sprintf("address=%s;db=mongodb;response_bytes=%d", address, n)
		_ = s.db.AddAsset(ctx, models.Asset{
			ScanID:   event.ScanID,
			Type:     "database_instance",
			Value:    address,
			Parent:   event.Target,
			Metadata: metadata,
		})
		_ = s.db.AddFinding(ctx, models.Finding{
			ScanID:      event.ScanID,
			Severity:    "high",
			Confidence:  "medium",
			Asset:       address,
			Title:       "Exposed MongoDB Database Endpoint",
			Evidence:    metadata,
			Remediation: "Enable MongoDB authorization (security.authorization: enabled) and bind to local networks.",
		})
		return []models.Event{{
			ScanID: event.ScanID,
			Type:   EventSpecializedDiscovered,
			Target: address,
			Data:   map[string]string{"category": "database", "vendor": "mongodb"},
		}}
	}
	return nil
}

func (s Specialized) checkMySQL(ctx context.Context, event models.Event, address string) []models.Event {
	conn, err := (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))

	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err == nil && n > 5 {
		// Protocol version (byte 4)
		protoVer := buf[4]
		versionStr := extractNullTerminated(buf[5:n])
		metadata := fmt.Sprintf("address=%s;db=mysql;proto_ver=%d;version=%s", address, protoVer, cleanEvidence(versionStr))

		_ = s.db.AddAsset(ctx, models.Asset{
			ScanID:   event.ScanID,
			Type:     "database_instance",
			Value:    address,
			Parent:   event.Target,
			Metadata: metadata,
		})
		_ = s.db.AddFinding(ctx, models.Finding{
			ScanID:      event.ScanID,
			Severity:    "info",
			Confidence:  "high",
			Asset:       address,
			Title:       "MySQL Database Server Handshake Responded",
			Evidence:    metadata,
			Remediation: "Ensure MySQL user passwords are strong and block external network exposure.",
		})
		return []models.Event{{
			ScanID: event.ScanID,
			Type:   EventSpecializedDiscovered,
			Target: address,
			Data:   map[string]string{"category": "database", "vendor": "mysql", "version": versionStr},
		}}
	}
	return nil
}

func (s Specialized) checkPostgreSQL(ctx context.Context, event models.Event, address string) []models.Event {
	conn, err := (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))

	// SSLRequest PDU: len=8, code=80877103
	sslReq := []byte{0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f}
	if _, err := conn.Write(sslReq); err != nil {
		return nil
	}

	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err == nil && n > 0 && (buf[0] == 'S' || buf[0] == 'N') {
		sslSupported := buf[0] == 'S'
		metadata := fmt.Sprintf("address=%s;db=postgresql;ssl_supported=%t", address, sslSupported)
		_ = s.db.AddAsset(ctx, models.Asset{
			ScanID:   event.ScanID,
			Type:     "database_instance",
			Value:    address,
			Parent:   event.Target,
			Metadata: metadata,
		})
		return []models.Event{{
			ScanID: event.ScanID,
			Type:   EventSpecializedDiscovered,
			Target: address,
			Data:   map[string]string{"category": "database", "vendor": "postgresql"},
		}}
	}
	return nil
}

func (s Specialized) checkMSSQL(ctx context.Context, event models.Event, address string) []models.Event {
	conn, err := (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))

	// TDS Pre-login packet
	prelogin := []byte{
		0x12, 0x01, 0x00, 0x1d, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,
		0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x01, 0xff,
		0x00, 0x00, 0x00, 0x00, 0x00,
	}

	if _, err := conn.Write(prelogin); err != nil {
		return nil
	}

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err == nil && n > 8 && buf[0] == 0x04 {
		metadata := fmt.Sprintf("address=%s;db=mssql;tds_response_bytes=%d", address, n)
		_ = s.db.AddAsset(ctx, models.Asset{
			ScanID:   event.ScanID,
			Type:     "database_instance",
			Value:    address,
			Parent:   event.Target,
			Metadata: metadata,
		})
		return []models.Event{{
			ScanID: event.ScanID,
			Type:   EventSpecializedDiscovered,
			Target: address,
			Data:   map[string]string{"category": "database", "vendor": "mssql"},
		}}
	}
	return nil
}

func (s Specialized) checkGenericDB(ctx context.Context, event models.Event, address string, port int) []models.Event {
	metadata := fmt.Sprintf("address=%s;port=%d;generic=true", address, port)
	_ = s.db.AddAsset(ctx, models.Asset{
		ScanID:   event.ScanID,
		Type:     "database_service",
		Value:    address,
		Parent:   event.Target,
		Metadata: metadata,
	})
	return []models.Event{{
		ScanID: event.ScanID,
		Type:   EventSpecializedDiscovered,
		Target: address,
		Data:   map[string]string{"category": "database", "port": strconv.Itoa(port)},
	}}
}

func extractNullTerminated(data []byte) string {
	idx := bytes.IndexByte(data, 0x00)
	if idx >= 0 {
		return string(data[:idx])
	}
	return string(data)
}
