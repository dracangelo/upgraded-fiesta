package plugin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"enumscan/internal/models"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

const PluginExecuteMethod = "/enumscan.plugin.v1.Plugin/Execute"

type GRPCHost struct {
	manifest *PluginManifest
	guard    *PermissionGuard
}

func NewGRPCHost(manifest *PluginManifest) *GRPCHost {
	return &GRPCHost{manifest: manifest, guard: NewPermissionGuard(manifest.Permissions)}
}

type PluginRequest struct {
	Event models.Event `json:"event"`
}

type PluginResponse struct {
	Events   []models.Event   `json:"events,omitempty"`
	Assets   []models.Asset   `json:"assets,omitempty"`
	Findings []models.Finding `json:"findings,omitempty"`
	Error    string           `json:"error,omitempty"`
}

func (h *GRPCHost) Execute(ctx context.Context, event models.Event) (*PluginResponse, error) {
	target, transport, err := pluginGRPCTarget(h.manifest.Exec)
	if err != nil {
		return nil, err
	}
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(callCtx, target, grpc.WithTransportCredentials(transport), grpc.WithBlock())
	if err != nil {
		return nil, fmt.Errorf("connect gRPC plugin %s: %w", h.manifest.Name, err)
	}
	defer connection.Close()
	requestMap, err := jsonObject(PluginRequest{Event: event})
	if err != nil {
		return nil, fmt.Errorf("marshal plugin request: %w", err)
	}
	request, err := structpb.NewStruct(requestMap)
	if err != nil {
		return nil, fmt.Errorf("construct plugin request: %w", err)
	}
	response := &structpb.Struct{}
	if err := connection.Invoke(callCtx, PluginExecuteMethod, request, response); err != nil {
		return nil, fmt.Errorf("execute gRPC plugin %s: %w", h.manifest.Name, err)
	}
	encoded, _ := json.Marshal(response.AsMap())
	var result PluginResponse
	if err := json.Unmarshal(encoded, &result); err != nil {
		return nil, fmt.Errorf("decode gRPC plugin output: %w", err)
	}
	if result.Error != "" {
		return nil, fmt.Errorf("plugin execution error: %s", boundedLuaString(result.Error, 300))
	}
	if len(result.Assets)+len(result.Findings)+len(result.Events) > 300 {
		return nil, fmt.Errorf("plugin output limit exceeded")
	}
	if len(result.Assets) > 0 || len(result.Findings) > 0 {
		if err := h.guard.Check(PermissionStoreWrite); err != nil {
			return nil, err
		}
	}
	for index := range result.Assets {
		result.Assets[index].ScanID = event.ScanID
	}
	for index := range result.Findings {
		result.Findings[index].ScanID = event.ScanID
	}
	for index := range result.Events {
		result.Events[index].ScanID = event.ScanID
	}
	return &result, nil
}

func pluginGRPCTarget(raw string) (string, credentials.TransportCredentials, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "grpc" && parsed.Scheme != "grpcs") {
		return "", nil, fmt.Errorf("gRPC plugin exec must be grpc:// or grpcs:// host:port")
	}
	host := parsed.Hostname()
	if parsed.Scheme == "grpc" {
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", nil, fmt.Errorf("plaintext gRPC plugins are allowed only on loopback")
		}
		return parsed.Host, insecure.NewCredentials(), nil
	}
	return parsed.Host, credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}), nil
}

func jsonObject(value any) (map[string]any, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	err = json.Unmarshal(encoded, &result)
	return result, err
}
