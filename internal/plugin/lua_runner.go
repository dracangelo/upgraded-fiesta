package plugin

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"enumscan/internal/models"
)

type LuaRunner struct {
	manifest *PluginManifest
	guard    *PermissionGuard
}

func NewLuaRunner(manifest *PluginManifest) *LuaRunner {
	return &LuaRunner{
		manifest: manifest,
		guard:    NewPermissionGuard(manifest.Permissions),
	}
}

type LuaExecResult struct {
	Events   []models.Event
	Assets   []models.Asset
	Findings []models.Finding
}

func (l *LuaRunner) Execute(ctx context.Context, event models.Event) (*LuaExecResult, error) {
	scriptData, err := os.ReadFile(l.manifest.Exec)
	if err != nil {
		return nil, fmt.Errorf("read lua script %s: %w", l.manifest.Exec, err)
	}

	result := &LuaExecResult{}
	script := string(scriptData)

	// Lightweight Lua-style DSL parsing / execution engine for standard check templates
	if strings.Contains(script, "http_get") {
		if err := l.guard.Check(PermissionNetwork); err != nil {
			return nil, err
		}

		targetURL := event.Target
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			targetURL = "http://" + targetURL
		}

		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err == nil {
			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				body := string(bodyBytes)

				if strings.Contains(script, "add_finding") && (resp.StatusCode == 200 || strings.Contains(body, "admin")) {
					if err := l.guard.Check(PermissionStoreWrite); err == nil {
						result.Findings = append(result.Findings, models.Finding{
							ScanID:      event.ScanID,
							Severity:    "info",
							Confidence:  "high",
							Asset:       event.Target,
							Title:       fmt.Sprintf("Lua Plugin [%s] HTTP Match", l.manifest.Name),
							Evidence:    fmt.Sprintf("status=%d;body_snippet=%s", resp.StatusCode, cleanSnippet(body)),
							Remediation: "Review Lua plugin findings.",
						})
					}
				}
			}
		}
	}

	if strings.Contains(script, "tcp_probe") {
		if err := l.guard.Check(PermissionNetwork); err != nil {
			return nil, err
		}

		conn, err := net.DialTimeout("tcp", event.Target, 2*time.Second)
		if err == nil {
			defer conn.Close()
			if l.guard.Has(PermissionStoreWrite) {
				result.Assets = append(result.Assets, models.Asset{
					ScanID:   event.ScanID,
					Type:     "lua_probe_success",
					Value:    event.Target,
					Parent:   event.Target,
					Metadata: fmt.Sprintf("plugin=%s", l.manifest.Name),
				})
			}
		}
	}

	return result, nil
}

func cleanSnippet(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.TrimSpace(s)
	if len(s) > 100 {
		return s[:100]
	}
	return s
}
