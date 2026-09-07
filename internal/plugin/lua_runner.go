package plugin

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"enumscan/internal/models"
	lua "github.com/yuin/gopher-lua"
)

type LuaRunner struct {
	manifest *PluginManifest
	guard    *PermissionGuard
}

func NewLuaRunner(manifest *PluginManifest) *LuaRunner {
	return &LuaRunner{manifest: manifest, guard: NewPermissionGuard(manifest.Permissions)}
}

type LuaExecResult struct {
	Events   []models.Event
	Assets   []models.Asset
	Findings []models.Finding
}

func (l *LuaRunner) Execute(ctx context.Context, event models.Event) (*LuaExecResult, error) {
	state := lua.NewState(lua.Options{SkipOpenLibs: true})
	defer state.Close()
	for _, library := range []struct {
		name string
		fn   lua.LGFunction
	}{{lua.BaseLibName, lua.OpenBase}, {lua.TabLibName, lua.OpenTable}, {lua.StringLibName, lua.OpenString}, {lua.MathLibName, lua.OpenMath}} {
		if err := state.CallByParam(lua.P{Fn: state.NewFunction(library.fn), NRet: 0, Protect: true}, lua.LString(library.name)); err != nil {
			return nil, fmt.Errorf("open Lua library: %w", err)
		}
	}
	state.SetContext(ctx)
	result := &LuaExecResult{}
	eventTable := state.NewTable()
	eventTable.RawSetString("scan_id", lua.LString(event.ScanID))
	eventTable.RawSetString("type", lua.LString(event.Type))
	eventTable.RawSetString("target", lua.LString(event.Target))
	data := state.NewTable()
	for key, value := range event.Data {
		data.RawSetString(key, lua.LString(value))
	}
	eventTable.RawSetString("data", data)
	state.SetGlobal("event", eventTable)

	state.SetGlobal("http_get", state.NewFunction(func(L *lua.LState) int {
		if err := l.guard.Check(PermissionNetwork); err != nil {
			L.RaiseError("%v", err)
		}
		raw := L.CheckString(1)
		if !samePluginTarget(raw, event.Target) {
			L.RaiseError("network target is outside the triggering event")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedHTTPURL(raw), nil)
		if err != nil {
			L.RaiseError("invalid URL")
		}
		client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := client.Do(req)
		if err != nil {
			L.Push(lua.LNil)
			return 1
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		response := L.NewTable()
		response.RawSetString("status", lua.LNumber(resp.StatusCode))
		response.RawSetString("body", lua.LString(body))
		L.Push(response)
		return 1
	}))
	state.SetGlobal("add_asset", state.NewFunction(func(L *lua.LState) int {
		if err := l.guard.Check(PermissionStoreWrite); err != nil {
			L.RaiseError("%v", err)
		}
		if len(result.Assets) >= 100 {
			L.RaiseError("plugin output limit exceeded")
		}
		result.Assets = append(result.Assets, models.Asset{ScanID: event.ScanID, Type: boundedLuaString(L.CheckString(1), 64), Value: boundedLuaString(L.CheckString(2), 2048), Parent: event.Target, Metadata: "plugin=" + l.manifest.Name})
		return 0
	}))
	state.SetGlobal("add_finding", state.NewFunction(func(L *lua.LState) int {
		if err := l.guard.Check(PermissionStoreWrite); err != nil {
			L.RaiseError("%v", err)
		}
		if len(result.Findings) >= 100 {
			L.RaiseError("plugin output limit exceeded")
		}
		result.Findings = append(result.Findings, models.Finding{ScanID: event.ScanID, Severity: boundedLuaString(L.OptString(2, "info"), 16), Confidence: "heuristic", Asset: event.Target, Title: boundedLuaString(L.CheckString(1), 200), Evidence: "Reported by signed Lua plugin " + l.manifest.Name, Remediation: "Review the plugin finding and underlying evidence."})
		return 0
	}))
	state.SetGlobal("add_event", state.NewFunction(func(L *lua.LState) int {
		if len(result.Events) >= 100 {
			L.RaiseError("plugin output limit exceeded")
		}
		result.Events = append(result.Events, models.Event{ScanID: event.ScanID, Type: boundedLuaString(L.CheckString(1), 128), Target: event.Target})
		return 0
	}))

	if err := state.DoFile(l.manifest.Exec); err != nil {
		return nil, fmt.Errorf("execute Lua plugin %s: %w", l.manifest.Name, err)
	}
	return result, nil
}

func normalizedHTTPURL(raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	return "http://" + raw
}

func samePluginTarget(raw, target string) bool {
	left, errLeft := url.Parse(normalizedHTTPURL(raw))
	right, errRight := url.Parse(normalizedHTTPURL(target))
	return errLeft == nil && errRight == nil && strings.EqualFold(left.Hostname(), right.Hostname()) && left.Port() == right.Port()
}

func boundedLuaString(value string, limit int) string {
	value = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " "))
	if len(value) > limit {
		return value[:limit]
	}
	return value
}
