package inventory

import (
	"fmt"
	"strings"
)

type CPENormalizer struct{}

func NewCPENormalizer() *CPENormalizer {
	return &CPENormalizer{}
}

func (c *CPENormalizer) NormalizeToCPE23(part, vendor, product, version string) string {
	if part == "" {
		part = "a"
	}
	vendor = sanitizeCPEComponent(vendor)
	product = sanitizeCPEComponent(product)
	version = sanitizeCPEComponent(version)

	if vendor == "" {
		vendor = "unknown"
	}
	if product == "" {
		product = "unknown"
	}
	if version == "" {
		version = "*"
	}

	return fmt.Sprintf("cpe:2.3:%s:%s:%s:%s:*:*:*:*:*:*:*", part, vendor, product, version)
}

func (c *CPENormalizer) ParseBannerToCPE(banner string) string {
	b := strings.ToLower(banner)
	if strings.Contains(b, "apache") {
		ver := extractVersion(b, "apache/")
		return c.NormalizeToCPE23("a", "apache", "http_server", ver)
	} else if strings.Contains(b, "nginx") {
		ver := extractVersion(b, "nginx/")
		return c.NormalizeToCPE23("a", "f5", "nginx", ver)
	} else if strings.Contains(b, "openssh") {
		ver := extractVersion(b, "openssh_")
		return c.NormalizeToCPE23("a", "openbsd", "openssh", ver)
	}
	return c.NormalizeToCPE23("a", "generic", "service", "*")
}

func sanitizeCPEComponent(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")
	return s
}

func extractVersion(s, prefix string) string {
	idx := strings.Index(s, prefix)
	if idx == -1 {
		return "*"
	}
	sub := s[idx+len(prefix):]
	fields := strings.Fields(sub)
	if len(fields) > 0 {
		ver := fields[0]
		ver = strings.Trim(ver, " ;,()")
		return ver
	}
	return "*"
}
