package modules

import "strings"

// PassiveProviderDefinition is the single source of truth for a supported
// third-party passive-intelligence integration. It contains no credentials,
// account state, or invented quota. Runtime request construction remains
// provider-specific because authentication and target compatibility differ.
type PassiveProviderDefinition struct {
	Name                string
	RequiredEnvironment []string
	Capabilities        []string
	Mode                string
	Note                string
	IPOnly              bool
	DomainOnly          bool
	RemoteProbe         bool
	APIVersion          string
}

var passiveProviderCatalog = map[string]PassiveProviderDefinition{
	"shodan":         {Name: "shodan", RequiredEnvironment: []string{"SHODAN_API_KEY"}, Capabilities: []string{"host intelligence", "observed services"}, Mode: "credentialed third-party API", IPOnly: true, RemoteProbe: true, APIVersion: "v1"},
	"censys":         {Name: "censys", RequiredEnvironment: []string{"CENSYS_API_ID", "CENSYS_API_SECRET"}, Capabilities: []string{"host intelligence", "observed services"}, Mode: "credentialed third-party API", IPOnly: true, RemoteProbe: true, APIVersion: "v2"},
	"securitytrails": {Name: "securitytrails", RequiredEnvironment: []string{"SECURITYTRAILS_API_KEY"}, Capabilities: []string{"subdomain intelligence"}, Mode: "credentialed third-party API", DomainOnly: true, RemoteProbe: true, APIVersion: "v1"},
	"fofa":           {Name: "fofa", RequiredEnvironment: []string{"FOFA_EMAIL", "FOFA_API_KEY"}, Capabilities: []string{"internet search intelligence"}, Mode: "credentialed third-party API", RemoteProbe: true, APIVersion: "v1"},
	"virustotal":     {Name: "virustotal", RequiredEnvironment: []string{"VIRUSTOTAL_API_KEY"}, Capabilities: []string{"domain intelligence", "passive URLs"}, Mode: "credentialed third-party API", RemoteProbe: true, APIVersion: "v3"},
	"github":         {Name: "github", RequiredEnvironment: []string{"GITHUB_TOKEN"}, Capabilities: []string{"public code search"}, Mode: "credentialed third-party API", RemoteProbe: true, APIVersion: "2026-03-10"},
	"gitlab":         {Name: "gitlab", RequiredEnvironment: []string{"GITLAB_TOKEN"}, Capabilities: []string{"code search"}, Mode: "credentialed third-party API", Note: "GITLAB_API_URL is optional for a self-hosted GitLab API endpoint.", RemoteProbe: true, APIVersion: "v4"},
	"hunter":         {Name: "hunter", RequiredEnvironment: []string{"HUNTER_API_KEY"}, Capabilities: []string{"domain email-pattern intelligence"}, Mode: "credentialed third-party API", DomainOnly: true, RemoteProbe: true, APIVersion: "v2"},
	"whoisxml":       {Name: "whoisxml", RequiredEnvironment: []string{"WHOISXML_API_KEY"}, Capabilities: []string{"subdomain intelligence"}, Mode: "credentialed third-party API", DomainOnly: true, RemoteProbe: true, APIVersion: "v2"},
	"hibp":           {Name: "hibp", RequiredEnvironment: []string{"HIBP_API_KEY"}, Capabilities: []string{"verified-domain breach summary"}, Mode: "credentialed third-party API", Note: "Domain lookup succeeds only for domains verified in the HIBP account; email aliases are discarded before persistence.", DomainOnly: true, RemoteProbe: true, APIVersion: "v3"},
	"dnsdb":          {Name: "dnsdb", RequiredEnvironment: []string{"DNSDB_API_KEY"}, Capabilities: []string{"passive DNS rrsets"}, Mode: "credentialed third-party API", DomainOnly: true, RemoteProbe: true, APIVersion: "v2"},
	"circl_cve":      {Name: "circl_cve", Capabilities: []string{"CVE search for fingerprinted products"}, Mode: "unauthenticated third-party API", Note: "Queried only for a validated CPE vendor/product from service fingerprinting.", RemoteProbe: true, APIVersion: "v1"},
	"abuseipdb":      {Name: "abuseipdb", RequiredEnvironment: []string{"ABUSEIPDB_API_KEY"}, Capabilities: []string{"IP abuse reputation"}, Mode: "credentialed third-party API", IPOnly: true},
	"greynoise":      {Name: "greynoise", RequiredEnvironment: []string{"GREYNOISE_API_KEY"}, Capabilities: []string{"IP internet-noise context"}, Mode: "credentialed third-party API", IPOnly: true},
	"binaryedge":     {Name: "binaryedge", RequiredEnvironment: []string{"BINARYEDGE_API_KEY"}, Capabilities: []string{"observed IP services"}, Mode: "credentialed third-party API", IPOnly: true},
	"urlscan":        {Name: "urlscan", RequiredEnvironment: []string{"URLSCAN_API_KEY"}, Capabilities: []string{"historical web-scan search"}, Mode: "credentialed third-party API", RemoteProbe: true},
	"otx":            {Name: "otx", RequiredEnvironment: []string{"OTX_API_KEY"}, Capabilities: []string{"indicator context"}, Mode: "credentialed third-party API", RemoteProbe: true},
	"wayback":        {Name: "wayback", Capabilities: []string{"historical URL discovery"}, Mode: "unauthenticated third-party archive query", Note: "This source makes direct archive requests during a scan. Use offline historical URL import when the engagement does not authorize that external query."},
	"paste":          {Name: "paste", RequiredEnvironment: []string{"PASTE_MONITOR_URL"}, Capabilities: []string{"operator monitoring search"}, Mode: "operator-configured monitoring endpoint"},
	"bucket":         {Name: "bucket", Capabilities: []string{"public bucket presence"}, Mode: "direct public-cloud HTTPS presence checks", Note: "This sends scoped candidate-bucket HEAD requests. Enable it only when those direct checks are authorized."},
}

func passiveProviderDefinition(source string) (PassiveProviderDefinition, bool) {
	definition, ok := passiveProviderCatalog[strings.ToLower(strings.TrimSpace(source))]
	return definition, ok
}
