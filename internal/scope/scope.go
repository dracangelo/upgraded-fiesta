package scope

import (
	"net"
	"strings"
)

type Guard struct {
	entries []entry
}

type entry struct {
	raw  string
	ip   net.IP
	cidr *net.IPNet
}

func New(allowed []string) Guard {
	entries := make([]entry, 0, len(allowed))
	for _, item := range allowed {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		e := entry{raw: strings.ToLower(item)}
		if ip := net.ParseIP(item); ip != nil {
			e.ip = ip
		}
		if _, cidr, err := net.ParseCIDR(item); err == nil {
			e.cidr = cidr
		}
		entries = append(entries, e)
	}
	return Guard{entries: entries}
}

func (g Guard) Allowed(target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	// Strip scheme if present
	if idx := strings.Index(target, "://"); idx != -1 {
		target = target[idx+3:]
	}
	// Strip path/query if present
	if idx := strings.IndexAny(target, "/?#"); idx != -1 {
		target = target[:idx]
	}

	host := target
	if parsedHost, _, err := net.SplitHostPort(target); err == nil {
		host = parsedHost
	}

	ip := net.ParseIP(host)
	for _, e := range g.entries {
		switch {
		case e.cidr != nil && ip != nil && e.cidr.Contains(ip):
			return true
		case e.ip != nil && ip != nil && e.ip.Equal(ip):
			return true
		case e.raw == host:
			return true
		case strings.HasPrefix(e.raw, "*.") && (strings.HasSuffix(host, strings.TrimPrefix(e.raw, "*")) || host == strings.TrimPrefix(e.raw, "*.")):
			return true
		// Scope Inheritance: domain example.com covers sub.example.com
		case !strings.Contains(e.raw, "/") && !strings.Contains(e.raw, ":") && net.ParseIP(e.raw) == nil:
			if host == e.raw || strings.HasSuffix(host, "."+e.raw) {
				return true
			}
		}
	}
	return false
}
