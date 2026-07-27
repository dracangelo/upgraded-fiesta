package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"enumscan/internal/models"
)

type GRPCHost struct {
	manifest *PluginManifest
	guard    *PermissionGuard
}

func NewGRPCHost(manifest *PluginManifest) *GRPCHost {
	return &GRPCHost{
		manifest: manifest,
		guard:    NewPermissionGuard(manifest.Permissions),
	}
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
	reqData, err := json.Marshal(PluginRequest{Event: event})
	if err != nil {
		return nil, fmt.Errorf("marshal plugin request: %w", err)
	}

	cmd := exec.CommandContext(ctx, h.manifest.Exec)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("create plugin stdin pipe: %w", err)
	}

	go func() {
		defer stdin.Close()
		_, _ = stdin.Write(reqData)
	}()

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("execute plugin %s: %w", h.manifest.Name, err)
	}

	var resp PluginResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal plugin output: %w", err)
	}

	if resp.Error != "" {
		return nil, fmt.Errorf("plugin execution error: %s", resp.Error)
	}

	// Permission enforcement on outputs
	if len(resp.Assets) > 0 || len(resp.Findings) > 0 {
		if err := h.guard.Check(PermissionStoreWrite); err != nil {
			return nil, err
		}
	}

	return &resp, nil
}
