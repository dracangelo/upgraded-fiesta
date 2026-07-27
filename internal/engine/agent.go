package engine

import (
	"context"
	"fmt"
	"time"

	"enumscan/internal/models"
)

type RemoteAgent struct {
	ID          string
	Coordinator *Coordinator
}

func NewRemoteAgent(id string, coord *Coordinator) *RemoteAgent {
	return &RemoteAgent{
		ID:          id,
		Coordinator: coord,
	}
}

func (a *RemoteAgent) Run(ctx context.Context) error {
	a.Coordinator.RegisterAgent(a.ID, "localhost")

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			_ = a.Coordinator.Heartbeat(a.ID)
			evt, err := a.Coordinator.FetchTask(ctx)
			if err == nil && evt.Target != "" {
				// Process task locally on agent node
				finding := models.Finding{
					ScanID:     evt.ScanID,
					Severity:   "info",
					Confidence: "high",
					Asset:      evt.Target,
					Title:      fmt.Sprintf("Agent [%s] Processed %s", a.ID, evt.Type),
				}
				a.Coordinator.SubmitFinding(finding)
			}
		}
	}
}
