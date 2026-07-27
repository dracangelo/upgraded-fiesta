package engine

import (
	"context"
	"fmt"
	"strings"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/modules"
	"enumscan/internal/scheduler"
)

// ReenumerationPlanner turns material asset-change events into narrow,
// scope-checked follow-up work. It avoids a full scan when one service or URL
// changes, while allowing the normal scheduler chain to handle the result.
type ReenumerationPlanner struct{}

func (ReenumerationPlanner) Plan(change models.Event) []models.Event {
	if change.Type != "asset.changed" || change.Target == "" {
		return nil
	}
	kind := strings.ToLower(change.Data["kind"])
	switch kind {
	case "url", "certificate", "technology":
		if strings.HasPrefix(change.Target, "http://") || strings.HasPrefix(change.Target, "https://") {
			return []models.Event{{ScanID: change.ScanID, Type: modules.EventHTTPURL, Target: change.Target, Data: map[string]string{"reason": "asset_change"}}}
		}
	case "port", "service", "host":
		host := strings.Split(change.Target, ":")[0]
		return []models.Event{{ScanID: change.ScanID, Type: modules.EventHost, Target: host, Data: map[string]string{"reason": "asset_change"}}}
	}
	return nil
}

// RunRecurring schedules a fresh scan ID for each interval. The caller owns
// the context lifetime; cancelling it stops scheduled future scans.
func (e Engine) RunRecurring(ctx context.Context, interval time.Duration) *scheduler.CronScheduler {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	cron := scheduler.NewCronScheduler()
	for _, target := range e.cfg.Scan.Targets {
		target := target
		cron.AddRecurringScan("scan-"+target, e.cfg.Scan.Profile, target, interval, func(runCtx context.Context, task scheduler.ScheduledTask) error {
			cfg := e.cfg
			cfg.Scan.Targets = []string{task.Target}
			runner := New(cfg, e.db)
			scanID := fmt.Sprintf("scheduled-%d", time.Now().UTC().UnixNano())
			return runner.Run(runCtx, scanID)
		})
	}
	cron.Start(ctx)
	return cron
}
