package modules

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type Discovery struct {
	db     *store.SQLiteCLI
	guard  scope.Guard
	config models.DiscoveryConfig
}

func NewDiscovery(db *store.SQLiteCLI, guard scope.Guard, config models.DiscoveryConfig) Discovery {
	if config.CIDRMaxHosts <= 0 {
		config.CIDRMaxHosts = 256
	}
	return Discovery{db: db, guard: guard, config: config}
}

func (d Discovery) Name() string { return "discovery" }

func (d Discovery) Subscriptions() []string { return []string{EventTarget} }

func (d Discovery) Handle(ctx context.Context, event models.Event) ([]models.Event, error) {
	if !d.guard.Allowed(event.Target) {
		return nil, nil
	}
	_ = d.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "target", Value: event.Target})
	next := d.importCaptureObservations(ctx, event.ScanID, event.Target)

	if _, cidr, err := net.ParseCIDR(event.Target); err == nil {
		return append(next, d.expandCIDR(ctx, event.ScanID, event.Target, cidr)...), nil
	}

	next = append(next, models.Event{ScanID: event.ScanID, Type: EventHost, Target: event.Target})

	if ip := net.ParseIP(event.Target); ip == nil {
		next = append(next, d.importPassiveHosts(ctx, event.ScanID, event.Target)...)
		if d.config.EnableDNSDiscovery {
			d.detectWildcardDNS(ctx, event.ScanID, event.Target)
			d.detectDNSProviders(ctx, event.ScanID, event.Target)
			d.discoverDNSRecords(ctx, event.ScanID, event.Target)
			addrs, _ := net.DefaultResolver.LookupHost(ctx, event.Target)
			for _, addr := range addrs {
				if d.guard.Allowed(addr) {
					_ = d.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "ip", Value: addr, Parent: event.Target, Metadata: "source=dns_a_or_aaaa"})
					d.detectIPHints(ctx, event.ScanID, addr, event.Target)
					next = append(next, models.Event{ScanID: event.ScanID, Type: EventHost, Target: addr, Data: map[string]string{"hostname": event.Target, "source": "dns"}})
				}
			}
		}
	} else {
		d.reverseDNS(ctx, event.ScanID, event.Target)
		d.rdap(ctx, event.ScanID, event.Target)
		d.probeLiveHost(ctx, event.ScanID, event.Target, event.Target)
	}
	return next, nil
}

func (d Discovery) expandCIDR(ctx context.Context, scanID, target string, cidr *net.IPNet) []models.Event {
	next := make([]models.Event, 0)
	count := 0
	for ip := firstIP(cidr); ip != nil && cidr.Contains(ip) && count < d.config.CIDRMaxHosts; ip = nextIP(ip) {
		if skipCIDREndpoint(cidr, ip) {
			continue
		}
		value := ip.String()
		if !d.guard.Allowed(value) {
			continue
		}
		_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "ip", Value: value, Parent: target, Metadata: "source=cidr_expansion"})
		d.reverseDNS(ctx, scanID, value)
		d.rdap(ctx, scanID, value)
		d.probeLiveHost(ctx, scanID, value, target)
		next = append(next, models.Event{ScanID: scanID, Type: EventHost, Target: value, Data: map[string]string{"source": "cidr_expansion"}})
		count++
	}
	if count == d.config.CIDRMaxHosts {
		_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "discovery_note", Value: target, Metadata: fmt.Sprintf("cidr_expansion_truncated_at=%d", d.config.CIDRMaxHosts)})
	}
	return next
}

func (d Discovery) importPassiveHosts(ctx context.Context, scanID, parent string) []models.Event {
	hosts := make([]string, 0)
	for _, path := range d.config.PassiveDNSFiles {
		hosts = append(hosts, readHostLines(path)...)
	}
	for _, path := range d.config.CertificateTransparencyFiles {
		hosts = append(hosts, readHostLines(path)...)
	}
	next := make([]models.Event, 0, len(hosts))
	seen := make(map[string]bool)
	for _, host := range hosts {
		host = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(host)), "*.")
		if host == "" || seen[host] || !sameDomain(parent, host) || !d.guard.Allowed(host) {
			continue
		}
		seen[host] = true
		_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "hostname", Value: host, Parent: parent, Metadata: "source=passive_import"})
		next = append(next, models.Event{ScanID: scanID, Type: EventTarget, Target: host, Data: map[string]string{"source": "passive_import"}})
	}
	return next
}

func (d Discovery) detectWildcardDNS(ctx context.Context, scanID, domain string) {
	if !d.config.EnableWildcardDNS || net.ParseIP(domain) != nil {
		return
	}
	probe := fmt.Sprintf("enumscan-%d.%s", time.Now().UnixNano(), strings.TrimSuffix(domain, "."))
	addrs, err := net.DefaultResolver.LookupHost(ctx, probe)
	if err != nil || len(addrs) == 0 {
		return
	}
	_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "dns_wildcard", Value: domain, Metadata: "probe=" + probe + ";addresses=" + strings.Join(addrs, "|")})
}

func (d Discovery) detectDNSProviders(ctx context.Context, scanID, domain string) {
	cname, err := net.DefaultResolver.LookupCNAME(ctx, domain)
	if err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != "" && !strings.EqualFold(cname, domain) {
			_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "dns_cname", Value: cname, Parent: domain, Metadata: "source=dns_cname"})
		}
		d.recordProviderHints(ctx, scanID, domain, cname, "cname")
	}
	mxs, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err == nil {
		for _, mx := range mxs {
			_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "dns_mx", Value: strings.TrimSuffix(mx.Host, "."), Parent: domain, Metadata: fmt.Sprintf("preference=%d", mx.Pref)})
			d.recordProviderHints(ctx, scanID, domain, mx.Host, "mx")
		}
	}
	nss, err := net.DefaultResolver.LookupNS(ctx, domain)
	if err == nil {
		for _, ns := range nss {
			_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "dns_ns", Value: strings.TrimSuffix(ns.Host, "."), Parent: domain})
			d.recordProviderHints(ctx, scanID, domain, ns.Host, "ns")
		}
	}
}

func (d Discovery) detectIPHints(ctx context.Context, scanID, ip, parent string) {
	if !d.config.EnableDNSDiscovery {
		return
	}
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err == nil {
		for _, name := range names {
			name = strings.TrimSuffix(name, ".")
			_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "reverse_dns", Value: name, Parent: ip})
			d.recordProviderHints(ctx, scanID, parent, name, "ptr")
		}
	}
	d.rdap(ctx, scanID, ip)
}

func skipCIDREndpoint(network *net.IPNet, ip net.IP) bool {
	if network.IP.To4() == nil {
		return false
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || 32-ones < 2 {
		return false // /31 and /32 are point-to-point/single-host networks.
	}
	if ip.Equal(network.IP) {
		return true
	}
	next := nextIP(ip)
	return !network.Contains(next)
}

func (d Discovery) reverseDNS(ctx context.Context, scanID, ip string) {
	if !d.config.EnableReverseDNS || net.ParseIP(ip) == nil {
		return
	}
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil {
		return
	}
	for _, name := range names {
		_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "reverse_dns", Value: strings.TrimSuffix(name, "."), Parent: ip})
	}
}

func (d Discovery) rdap(ctx context.Context, scanID, ip string) {
	if !d.config.EnableRDAP || net.ParseIP(ip) == nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://rdap.org/ip/"+ip, nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var body struct {
		Handle string `json:"handle"`
		Name   string `json:"name"`
	}
	if json.NewDecoder(resp.Body).Decode(&body) != nil {
		return
	}
	if body.Handle != "" || body.Name != "" {
		_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "rdap_network", Value: strings.TrimSpace(body.Handle + " " + body.Name), Parent: ip, Metadata: "source=rdap.org"})
	}
}

func (d Discovery) recordProviderHints(ctx context.Context, scanID, parent, evidence, source string) {
	evidence = strings.ToLower(strings.TrimSuffix(evidence, "."))
	for _, hint := range providerHints {
		if strings.Contains(evidence, hint.Match) {
			_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: hint.Type, Value: hint.Name, Parent: parent, Metadata: "source=" + source + ";evidence=" + evidence})
		}
	}
}

func readHostLines(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	hosts := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, field := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ';' || r == '"' || r == '\'' || r == '[' || r == ']'
		}) {
			field = strings.TrimSpace(field)
			if looksLikeHostname(field) {
				hosts = append(hosts, field)
				break
			}
		}
	}
	return hosts
}

func looksLikeHostname(value string) bool {
	return strings.Contains(value, ".") && !strings.ContainsAny(value, " /\\:@")
}

func sameDomain(parent, host string) bool {
	parent = strings.TrimSuffix(strings.ToLower(parent), ".")
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == parent || strings.HasSuffix(host, "."+parent)
}

func firstIP(network *net.IPNet) net.IP {
	ip := network.IP.To4()
	if ip == nil {
		ip = network.IP.To16()
	}
	if ip == nil {
		return nil
	}
	return append(net.IP(nil), ip...)
}

func nextIP(ip net.IP) net.IP {
	next := append(net.IP(nil), ip...)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

var providerHints = []struct {
	Match string
	Type  string
	Name  string
}{
	{"cloudflare", "cdn", "Cloudflare"},
	{"cloudfront", "cdn", "Amazon CloudFront"},
	{"akamai", "cdn", "Akamai"},
	{"fastly", "cdn", "Fastly"},
	{"azureedge", "cdn", "Azure CDN"},
	{"trafficmanager", "load_balancer", "Azure Traffic Manager"},
	{"elb.amazonaws", "load_balancer", "AWS Elastic Load Balancing"},
	{"amazonaws", "cloud_provider", "AWS"},
	{"googleusercontent", "cloud_provider", "Google Cloud"},
	{"googlehosted", "cloud_provider", "Google Cloud"},
	{"azure", "cloud_provider", "Azure"},
	{"digitalocean", "cloud_provider", "DigitalOcean"},
	{"herokuapp", "cloud_provider", "Heroku"},
	{"netlify", "cloud_provider", "Netlify"},
	{"vercel", "cloud_provider", "Vercel"},
}
