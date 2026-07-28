package plugin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"enumscan/internal/models"
)

type PluginSandbox struct {
	maxExecTime time.Duration
}

func NewPluginSandbox(timeout time.Duration) *PluginSandbox {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &PluginSandbox{maxExecTime: timeout}
}

func (s *PluginSandbox) ExecuteSandboxed(ctx context.Context, fn func(ctx context.Context) ([]models.Event, error)) ([]models.Event, error) {
	ctxTimeout, cancel := context.WithTimeout(ctx, s.maxExecTime)
	defer cancel()

	type result struct {
		events []models.Event
		err    error
	}

	resChan := make(chan result, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				resChan <- result{nil, fmt.Errorf("plugin panic recovered: %v", r)}
			}
		}()
		events, err := fn(ctxTimeout)
		resChan <- result{events, err}
	}()

	select {
	case res := <-resChan:
		return res.events, res.err
	case <-ctxTimeout.Done():
		return nil, errors.New("plugin execution sandboxed: execution timeout exceeded")
	}
}
