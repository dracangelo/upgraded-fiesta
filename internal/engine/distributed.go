package engine

import (
	"context"
	"fmt"
	"sync"
	"time"

	"enumscan/internal/models"
)

type AgentStatus struct {
	ID            string    `json:"id"`
	Address       string    `json:"address"`
	LastHeartbeat time.Time `json:"last_heartbeat"`
	ActiveJobs    int       `json:"active_jobs"`
}

type Coordinator struct {
	mu        sync.RWMutex
	agents    map[string]*AgentStatus
	taskQueue chan models.Event
	results   chan models.Finding
}

func NewCoordinator() *Coordinator {
	return &Coordinator{
		agents:    make(map[string]*AgentStatus),
		taskQueue: make(chan models.Event, 500),
		results:   make(chan models.Finding, 500),
	}
}

func (c *Coordinator) RegisterAgent(id, address string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.agents[id] = &AgentStatus{
		ID:            id,
		Address:       address,
		LastHeartbeat: time.Now(),
	}
}

func (c *Coordinator) Heartbeat(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	agent, ok := c.agents[id]
	if !ok {
		return fmt.Errorf("agent %s not registered", id)
	}
	agent.LastHeartbeat = time.Now()
	return nil
}

func (c *Coordinator) Dispatch(evt models.Event) {
	c.taskQueue <- evt
}

func (c *Coordinator) FetchTask(ctx context.Context) (models.Event, error) {
	select {
	case evt := <-c.taskQueue:
		return evt, nil
	case <-ctx.Done():
		return models.Event{}, ctx.Err()
	}
}

func (c *Coordinator) SubmitFinding(finding models.Finding) {
	c.results <- finding
}

func (c *Coordinator) AgentCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.agents)
}
