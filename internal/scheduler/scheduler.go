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
	highQueue          chan models.Event
	normalQueue        chan models.Event
	lowQueue           chan models.Event
	done               chan struct{}
	wg                 sync.WaitGroup
	logger             *slog.Logger
	limiter            *targetLimiter
	deduper            *eventDeduper
	workers            sync.WaitGroup
	adaptive           *AdaptiveWorkerPool
	workerMu           sync.Mutex
	liveWorkers        int
	pendingRetirements int
	runtimeMu          sync.Mutex
	runtime            models.ScanRuntimeStats
	lastRuntimeWrite   time.Time
}

// EnableAdaptiveWorkers opts this scheduler into bounded live worker scaling.
// The configured concurrency remains the upper bound; fixed worker behaviour
// is preserved unless the engine explicitly calls this method.
func (s *Scheduler) EnableAdaptiveWorkers(minConcurrency int) {
	if minConcurrency < 1 {
		minConcurrency = 1
	}
	if minConcurrency > s.concurrency {
		minConcurrency = s.concurrency
	}
	s.adaptive = NewAdaptiveWorkerPool(minConcurrency, s.concurrency)
}

// SetScanID associates process-local queue statistics with one persisted scan.
// Engine instances create one scheduler per scan, so this remains unambiguous.
func (s *Scheduler) SetScanID(scanID string) {
	s.runtimeMu.Lock()
	s.runtime.ScanID = scanID
	s.runtime.WorkerCapacity = s.concurrency
	if s.adaptive != nil {
		s.runtime.WorkerCapacity = s.adaptive.Concurrency()
	}
	s.runtimeMu.Unlock()
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
		highQueue:          make(chan models.Event, 1024),
		normalQueue:        make(chan models.Event, 1024),
		lowQueue:           make(chan models.Event, 1024),
		done:               make(chan struct{}),
		logger:             logger,
		limiter:            newTargetLimiter(perTargetRateLimit),
		deduper:            newEventDeduper(100000),
	}
}

func (s *Scheduler) Register(module Module) {
	s.modules = append(s.modules, module)
}

// ChainFor reports the modules that will consume an event. It exposes the
// scheduler's event-driven chaining plan for diagnostics and automation.
func (s *Scheduler) ChainFor(eventType string) []string {
	names := make([]string, 0)
	for _, module := range s.modules {
		if subscribes(module, eventType) {
			names = append(names, module.Name())
		}
	}
	return names
}

func (s *Scheduler) Enqueue(event models.Event) {
	s.EnqueuePriority(event, priorityFor(event))
}

// EnqueuePriority places urgent target and host-discovery work ahead of
// lower-value enrichment. Priorities only affect scheduling order; all events
// retain the same persistence and checkpoint semantics.
func (s *Scheduler) EnqueuePriority(event models.Event, priority int) {
	if s.deduper.seen(event) {
		return
	}
	s.runtimeMu.Lock()
	if s.runtime.ScanID == "" {
		s.runtime.ScanID = event.ScanID
		s.runtime.WorkerCapacity = s.concurrency
		if s.adaptive != nil {
			s.runtime.WorkerCapacity = s.adaptive.Concurrency()
		}
	}
	s.runtime.EnqueuedEvents++
	s.runtimeMu.Unlock()
	s.wg.Add(1)
	s.queueForPriority(priority) <- event
}

func (s *Scheduler) Run(ctx context.Context, db store.RuntimeStore) error {
	errs := make(chan error, 1)
	s.persistRuntime(ctx, db, true)
	initialWorkers := s.concurrency
	if s.adaptive != nil {
		initialWorkers = s.adaptive.Concurrency()
	}
	for i := 0; i < initialWorkers; i++ {
		s.spawnWorker(ctx, db, errs)
	}
	s.wg.Wait()
	close(s.highQueue)
	close(s.normalQueue)
	close(s.lowQueue)
	close(s.done)
	s.workers.Wait()
	s.persistRuntime(ctx, db, true)
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
}

func (s *Scheduler) spawnWorker(ctx context.Context, db store.RuntimeStore, errs chan<- error) {
	s.workerMu.Lock()
	s.liveWorkers++
	s.workerMu.Unlock()
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		defer s.workerExited()
		s.worker(ctx, db, errs)
	}()
}

func (s *Scheduler) workerExited() {
	s.workerMu.Lock()
	if s.liveWorkers > 0 {
		s.liveWorkers--
	}
	if s.pendingRetirements > 0 {
		s.pendingRetirements--
	}
	s.workerMu.Unlock()
}

func (s *Scheduler) worker(ctx context.Context, db store.RuntimeStore, errs chan<- error) {
	s.adjustRuntimeWorkers(ctx, db, 1)
	defer s.adjustRuntimeWorkers(ctx, db, -1)
	for {
		if err := waitForScanResume(ctx, db, s.runtimeScanID()); err != nil {
			return
		}
		event, ok := s.nextEvent()
		if !ok {
			return
		}
		if event.ID == 0 {
			eventID, err := db.AddEvent(ctx, event)
			if err != nil {
				s.recordRun(ctx, db, event, "event_store", "failed", 0, err)
				select {
				case errs <- err:
				default:
				}
			}
			event.ID = eventID
		}
		for _, module := range s.modules {
			if subscribes(module, event.Type) {
				if err := waitForScanResume(ctx, db, event.ScanID); err != nil {
					s.wg.Done()
					return
				}
				moduleLog := s.logger.With(
					"scan_id", event.ScanID,
					"event_id", event.ID,
					"event_type", event.Type,
					"target", event.Target,
					"module", module.Name(),
				)
				status, err := db.CheckpointStatus(ctx, event.ScanID, module.Name(), event.Type, event.Target)
				if err != nil {
					s.recordRun(ctx, db, event, module.Name(), "failed", 0, err)
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
					s.recordRun(ctx, db, event, module.Name(), "failed", 0, err)
					select {
					case errs <- err:
					default:
					}
					continue
				}
				s.limiter.Wait(ctx, event.Target)
				moduleCtx, cancel := context.WithTimeout(ctx, s.moduleTimeout)
				moduleLog.Info("module started")
				s.adjustRunningModules(ctx, db, 1)
				started := time.Now()
				next, err := module.Handle(moduleCtx, event)
				duration := time.Since(started)
				cancel()
				s.adjustRunningModules(ctx, db, -1)
				s.recordModuleLatency(ctx, db, errs, duration)
				if err != nil {
					_ = db.UpsertCheckpoint(ctx, models.Checkpoint{ScanID: event.ScanID, Module: module.Name(), EventType: event.Type, Target: event.Target, Status: "failed", Error: err.Error()})
					s.recordRun(ctx, db, event, module.Name(), "failed", duration, err)
					moduleLog.Error("module failed", "error", err.Error())
					select {
					case errs <- err:
					default:
					}
					continue
				}
				_ = db.UpsertCheckpoint(ctx, models.Checkpoint{ScanID: event.ScanID, Module: module.Name(), EventType: event.Type, Target: event.Target, Status: "completed"})
				s.recordRun(ctx, db, event, module.Name(), "completed", duration, nil)
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
		s.runtimeMu.Lock()
		s.runtime.CompletedEvents++
		s.runtimeMu.Unlock()
		s.persistRuntime(ctx, db, false)
		s.wg.Done()
		if s.reserveAdaptiveRetirement() {
			return
		}
	}
}

func (s *Scheduler) recordModuleLatency(ctx context.Context, db store.RuntimeStore, errs chan<- error, duration time.Duration) {
	if s.adaptive == nil {
		return
	}
	s.adaptive.RecordLatency(duration)
	desired := s.adaptive.Concurrency()
	s.workerMu.Lock()
	additional := desired - s.liveWorkers
	s.workerMu.Unlock()
	for i := 0; i < additional; i++ {
		s.spawnWorker(ctx, db, errs)
	}
	s.runtimeMu.Lock()
	s.runtime.WorkerCapacity = desired
	s.runtimeMu.Unlock()
	s.persistRuntime(ctx, db, false)
}

func (s *Scheduler) reserveAdaptiveRetirement() bool {
	if s.adaptive == nil {
		return false
	}
	desired := s.adaptive.Concurrency()
	s.workerMu.Lock()
	defer s.workerMu.Unlock()
	if s.liveWorkers-s.pendingRetirements <= desired {
		return false
	}
	s.pendingRetirements++
	return true
}

func (s *Scheduler) runtimeScanID() string {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	return s.runtime.ScanID
}

// waitForScanResume provides cooperative pause/resume at safe scheduler
// boundaries. It never interrupts a module in progress, avoiding half-finished
// network operations; a pause takes effect before the next event or module.
func waitForScanResume(ctx context.Context, db store.RuntimeStore, scanID string) error {
	if db == nil || scanID == "" {
		return nil
	}
	for {
		status, err := db.GetScanStatus(ctx, scanID)
		if err != nil || status != "paused" {
			return err
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (s *Scheduler) adjustRuntimeWorkers(ctx context.Context, db store.RuntimeStore, delta int) {
	s.runtimeMu.Lock()
	s.runtime.ActiveWorkers += delta
	if s.runtime.ActiveWorkers < 0 {
		s.runtime.ActiveWorkers = 0
	}
	s.runtimeMu.Unlock()
	s.persistRuntime(ctx, db, delta < 0)
}

func (s *Scheduler) adjustRunningModules(ctx context.Context, db store.RuntimeStore, delta int) {
	s.runtimeMu.Lock()
	s.runtime.RunningModules += delta
	if s.runtime.RunningModules < 0 {
		s.runtime.RunningModules = 0
	}
	s.runtimeMu.Unlock()
	s.persistRuntime(ctx, db, delta < 0)
}

func (s *Scheduler) runtimeSnapshot() models.ScanRuntimeStats {
	s.runtimeMu.Lock()
	defer s.runtimeMu.Unlock()
	stats := s.runtime
	stats.QueueHigh = len(s.highQueue)
	stats.QueueNormal = len(s.normalQueue)
	stats.QueueLow = len(s.lowQueue)
	return stats
}

func (s *Scheduler) persistRuntime(ctx context.Context, db store.RuntimeStore, force bool) {
	if db == nil {
		return
	}
	now := time.Now()
	s.runtimeMu.Lock()
	if s.runtime.ScanID == "" || (!force && now.Sub(s.lastRuntimeWrite) < 250*time.Millisecond) {
		s.runtimeMu.Unlock()
		return
	}
	s.lastRuntimeWrite = now
	stats := s.runtime
	stats.QueueHigh = len(s.highQueue)
	stats.QueueNormal = len(s.normalQueue)
	stats.QueueLow = len(s.lowQueue)
	s.runtimeMu.Unlock()
	if err := db.UpsertRuntimeStats(ctx, stats); err != nil {
		s.logger.Debug("persist runtime stats", "scan_id", stats.ScanID, "error", err)
	}
}

func (s *Scheduler) queueForPriority(priority int) chan models.Event {
	switch priority {
	case PriorityHigh:
		return s.highQueue
	case PriorityLow:
		return s.lowQueue
	default:
		return s.normalQueue
	}
}

func priorityFor(event models.Event) int {
	switch event.Type {
	case "target", "host.discovered", "port.open":
		return PriorityHigh
	case "http.url", "asset.changed":
		return PriorityNormal
	default:
		return PriorityLow
	}
}

// nextEvent gives high-priority work a deterministic first chance before
// blocking for more work. Closed queues are removed from the select loop so
// worker shutdown cannot starve remaining queues.
func (s *Scheduler) nextEvent() (models.Event, bool) {
	high, normal, low := s.highQueue, s.normalQueue, s.lowQueue
	for high != nil || normal != nil || low != nil {
		select {
		case <-s.done:
			return models.Event{}, false
		default:
		}
		if high != nil {
			select {
			case event, ok := <-high:
				if !ok {
					high = nil
				} else {
					return event, true
				}
			default:
			}
		}
		if normal != nil {
			select {
			case event, ok := <-normal:
				if !ok {
					normal = nil
				} else {
					return event, true
				}
			default:
			}
		}
		if low != nil {
			select {
			case event, ok := <-low:
				if !ok {
					low = nil
				} else {
					return event, true
				}
			default:
			}
		}

		select {
		case <-s.done:
			return models.Event{}, false
		case event, ok := <-high:
			if !ok {
				high = nil
			} else {
				return event, true
			}
		case event, ok := <-normal:
			if !ok {
				normal = nil
			} else {
				return event, true
			}
		case event, ok := <-low:
			if !ok {
				low = nil
			} else {
				return event, true
			}
		}
	}
	return models.Event{}, false
}

func (s *Scheduler) recordRun(ctx context.Context, db store.RuntimeStore, event models.Event, module, status string, duration time.Duration, runErr error) {
	message := ""
	if runErr != nil {
		message = runErr.Error()
	}
	if err := db.RecordModuleRun(ctx, models.ModuleRun{ScanID: event.ScanID, Module: module, EventType: event.Type, Target: event.Target, Status: status, Duration: duration, Error: message}); err != nil {
		s.logger.Error("record module outcome", "scan_id", event.ScanID, "module", module, "error", err)
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
