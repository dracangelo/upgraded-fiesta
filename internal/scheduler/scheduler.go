package scheduler

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/store"
)

type Module interface {
	Name() string
	Subscriptions() []string
	Handle(context.Context, models.Event) ([]models.Event, error)
}

type Scheduler struct {
	concurrency        int
	globalRateLimit    time.Duration
	perTargetRateLimit time.Duration
	moduleTimeout      time.Duration
	modules            []Module
	queue              chan models.Event
	wg                 sync.WaitGroup
	logger             *slog.Logger
	limiter            *targetLimiter
}

func New(concurrency int, globalRateLimit, perTargetRateLimit, moduleTimeout time.Duration, logger *slog.Logger) *Scheduler {
	if concurrency < 1 {
		concurrency = 1
	}
	if moduleTimeout <= 0 {
		moduleTimeout = 30 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Scheduler{
		concurrency:        concurrency,
		globalRateLimit:    globalRateLimit,
		perTargetRateLimit: perTargetRateLimit,
		moduleTimeout:      moduleTimeout,
		queue:              make(chan models.Event, 1024),
		logger:             logger,
		limiter:            newTargetLimiter(perTargetRateLimit),
	}
}

func (s *Scheduler) Register(module Module) {
	s.modules = append(s.modules, module)
}

func (s *Scheduler) Enqueue(event models.Event) {
	s.wg.Add(1)
	s.queue <- event
}

func (s *Scheduler) Run(ctx context.Context, db *store.SQLiteCLI) error {
	errs := make(chan error, 1)
	for i := 0; i < s.concurrency; i++ {
		go s.worker(ctx, db, errs)
	}
	s.wg.Wait()
	close(s.queue)
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
}

func (s *Scheduler) worker(ctx context.Context, db *store.SQLiteCLI, errs chan<- error) {
	for event := range s.queue {
		if event.ID == 0 {
			eventID, err := db.AddEvent(ctx, event)
			if err != nil {
				select {
				case errs <- err:
				default:
				}
			}
			event.ID = eventID
		}
		for _, module := range s.modules {
			if subscribes(module, event.Type) {
				moduleLog := s.logger.With(
					"scan_id", event.ScanID,
					"event_id", event.ID,
					"event_type", event.Type,
					"target", event.Target,
					"module", module.Name(),
				)
				status, err := db.CheckpointStatus(ctx, event.ScanID, module.Name(), event.Type, event.Target)
				if err != nil {
					select {
					case errs <- err:
					default:
					}
					continue
				}
				if status == "completed" {
					moduleLog.Info("checkpoint skipped")
					continue
				}
				if err := db.UpsertCheckpoint(ctx, models.Checkpoint{ScanID: event.ScanID, Module: module.Name(), EventType: event.Type, Target: event.Target, Status: "running"}); err != nil {
					select {
					case errs <- err:
					default:
					}
					continue
				}
				s.limiter.Wait(ctx, event.Target)
				moduleCtx, cancel := context.WithTimeout(ctx, s.moduleTimeout)
				moduleLog.Info("module started")
				next, err := module.Handle(moduleCtx, event)
				cancel()
				if err != nil {
					_ = db.UpsertCheckpoint(ctx, models.Checkpoint{ScanID: event.ScanID, Module: module.Name(), EventType: event.Type, Target: event.Target, Status: "failed", Error: err.Error()})
					moduleLog.Error("module failed", "error", err.Error())
					select {
					case errs <- err:
					default:
					}
					continue
				}
				_ = db.UpsertCheckpoint(ctx, models.Checkpoint{ScanID: event.ScanID, Module: module.Name(), EventType: event.Type, Target: event.Target, Status: "completed"})
				moduleLog.Info("module completed", "new_events", len(next))
				for _, item := range next {
					s.Enqueue(item)
				}
				if s.globalRateLimit > 0 {
					select {
					case <-ctx.Done():
					case <-time.After(s.globalRateLimit):
					}
				}
			}
		}
		s.wg.Done()
	}
}

type targetLimiter struct {
	delay time.Duration
	mu    sync.Mutex
	next  map[string]time.Time
}

func newTargetLimiter(delay time.Duration) *targetLimiter {
	return &targetLimiter{delay: delay, next: make(map[string]time.Time)}
}

func (l *targetLimiter) Wait(ctx context.Context, target string) {
	if l.delay <= 0 {
		return
	}
	l.mu.Lock()
	now := time.Now()
	waitUntil := l.next[target]
	if waitUntil.Before(now) {
		waitUntil = now
	}
	l.next[target] = waitUntil.Add(l.delay)
	l.mu.Unlock()

	if wait := time.Until(waitUntil); wait > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(wait):
		}
	}
}

func subscribes(module Module, eventType string) bool {
	for _, sub := range module.Subscriptions() {
		if sub == eventType {
			return true
		}
	}
	return false
}
