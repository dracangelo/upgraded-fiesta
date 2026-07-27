package plugin

import (
	"fmt"
	"strings"
)

const (
	PermissionNetwork    = "network"
	PermissionStoreRead  = "store_read"
	PermissionStoreWrite = "store_write"
)

type PermissionGuard struct {
	allowed map[string]bool
}

func NewPermissionGuard(perms []string) *PermissionGuard {
	allowed := make(map[string]bool)
	for _, p := range perms {
		allowed[strings.ToLower(strings.TrimSpace(p))] = true
	}
	return &PermissionGuard{allowed: allowed}
}

func (p *PermissionGuard) Check(perm string) error {
	perm = strings.ToLower(strings.TrimSpace(perm))
	if !p.allowed[perm] {
		return fmt.Errorf("permission denied: plugin lacks '%s' permission", perm)
	}
	return nil
}

func (p *PermissionGuard) Has(perm string) bool {
	return p.allowed[strings.ToLower(strings.TrimSpace(perm))]
}
