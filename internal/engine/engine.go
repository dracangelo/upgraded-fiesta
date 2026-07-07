package engine

import (
	"context"
	"fmt"
	"time"

	"enumscan/internal/logging"
	"enumscan/internal/models"
	"enumscan/internal/modules"
	"enumscan/internal/scheduler"
	"enumscan/internal/scope"
	"enumscan/internal/store"
)

type Engine struct {
	cfg   models.Config
	db    *store.SQLiteCLI
	guard scope.Guard
}

func New(cfg models.Config, db *store.SQLiteCLI) Engine {
	return Engine{cfg: cfg, db: db, guard: scope.New(cfg.Scope.AllowedTargets)}
}

func (e Engine) Run(ctx context.Context, scanID string) error {
	for _, target := range e.cfg.Scan.Targets {
		if !e.guard.Allowed(target) {
			return fmt.Errorf("target %q is outside configured scope", target)
		}
	}

	if err := e.db.StartScan(ctx, scanID); err != nil {
		return err
	}

	queue := scheduler.New(
		e.cfg.Scheduler.Concurrency,
		time.Duration(e.cfg.Scheduler.GlobalRateLimitMS)*time.Millisecond,
		time.Duration(e.cfg.Scheduler.PerTargetRateLimitMS)*time.Millisecond,
		time.Duration(e.cfg.Scheduler.ModuleTimeoutMS)*time.Millisecond,
		logging.New(),
	)
	queue.Register(modules.NewDiscovery(e.db, e.guard, e.cfg.Discovery))
	queue.Register(modules.NewPortScan(e.db, e.guard, e.cfg.Scan.Ports))
	queue.Register(modules.NewHTTP(e.db, e.guard))

	previous, err := e.db.Events(ctx, scanID)
	if err != nil {
		return err
	}
	for _, event := range previous {
		queue.Enqueue(event)
	}
	for _, target := range e.cfg.Scan.Targets {
		queue.Enqueue(models.Event{ScanID: scanID, Type: modules.EventTarget, Target: target})
	}
	if err := queue.Run(ctx, e.db); err != nil {
		_ = e.db.FinishScan(ctx, scanID, "failed", err.Error())
		return err
	}
	return e.db.FinishScan(ctx, scanID, "completed", "")
}
