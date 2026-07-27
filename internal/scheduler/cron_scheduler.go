package scheduler

import (
	"context"
	"sync"
	"time"
)

type ScheduledTask struct {
	ID        string
	Profile   string
	Target    string
	Interval  time.Duration
	LastRun   time.Time
	NextRun   time.Time
	Enabled   bool
	RunAction func(ctx context.Context, task ScheduledTask) error
}

type CronScheduler struct {
	mu     sync.RWMutex
	tasks  map[string]*ScheduledTask
	ticker *time.Ticker
	stop   chan struct{}
}

func NewCronScheduler() *CronScheduler {
	return &CronScheduler{
		tasks: make(map[string]*ScheduledTask),
		stop:  make(chan struct{}),
	}
}

func (cs *CronScheduler) AddRecurringScan(id, profile, target string, interval time.Duration, action func(ctx context.Context, task ScheduledTask) error) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	now := time.Now()
	cs.tasks[id] = &ScheduledTask{
		ID:        id,
		Profile:   profile,
		Target:    target,
		Interval:  interval,
		NextRun:   now.Add(interval),
		Enabled:   true,
		RunAction: action,
	}
}

func (cs *CronScheduler) Start(ctx context.Context) {
	cs.ticker = time.NewTicker(10 * time.Millisecond)
	go func() {
		for {
			select {
			case <-cs.ticker.C:
				cs.checkAndRun(ctx)
			case <-cs.stop:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (cs *CronScheduler) checkAndRun(ctx context.Context) {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	now := time.Now()
	for _, task := range cs.tasks {
		if task.Enabled && !now.Before(task.NextRun) {
			task.LastRun = now
			task.NextRun = now.Add(task.Interval)
			if task.RunAction != nil {
				go func(t ScheduledTask) {
					_ = t.RunAction(ctx, t)
				}(*task)
			}
		}
	}
}

func (cs *CronScheduler) Stop() {
	if cs.ticker != nil {
		cs.ticker.Stop()
	}
	close(cs.stop)
}

func ParseProfileInterval(profile string) time.Duration {
	switch profile {
	case "hourly":
		return 1 * time.Hour
	case "daily":
		return 24 * time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}

func (cs *CronScheduler) TaskCount() int {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	return len(cs.tasks)
}
