package modules

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"enumscan/internal/models"
)

// discoverDNSAuthorityRecords uses the operator host's configured resolver to
// obtain record types not exposed by the Go standard resolver. It issues only
// SOA and CAA questions for the in-scope domain being enumerated.
func (d Discovery) discoverDNSAuthorityRecords(ctx context.Context, scanID, domain string) {
	resolver, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(resolver.Servers) == 0 {
		return
	}
	server := net.JoinHostPort(resolver.Servers[0], resolver.Port)
	for _, questionType := range []uint16{dns.TypeSOA, dns.TypeCAA} {
		answers, err := lookupDNSAnswers(ctx, server, domain, questionType)
		if err != nil {
			continue
		}
		for _, answer := range answers {
			switch record := answer.(type) {
			case *dns.SOA:
				metadata := fmt.Sprintf("mname=%s;rname=%s;serial=%d;refresh=%d;retry=%d;expire=%d;minimum=%d;source=resolver", strings.TrimSuffix(record.Ns, "."), strings.TrimSuffix(record.Mbox, "."), record.Serial, record.Refresh, record.Retry, record.Expire, record.Minttl)
				_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "dns_soa", Value: strings.TrimSuffix(record.Ns, "."), Parent: domain, Metadata: metadata})
			case *dns.CAA:
				metadata := fmt.Sprintf("flags=%d;tag=%s;source=resolver", record.Flag, record.Tag)
				_ = d.db.AddAsset(ctx, models.Asset{ScanID: scanID, Type: "dns_caa", Value: record.Value, Parent: domain, Metadata: metadata})
			}
		}
	}
}

func lookupDNSAnswers(ctx context.Context, server, domain string, questionType uint16) ([]dns.RR, error) {
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(domain), questionType)
	client := &dns.Client{Timeout: 3 * time.Second}
	response, _, err := client.ExchangeContext(ctx, message, server)
	if err != nil {
		return nil, err
	}
	if response.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS response code %s", dns.RcodeToString[response.Rcode])
	}
	return response.Answer, nil
}
