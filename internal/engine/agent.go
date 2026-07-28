package engine

import (
	"context"
	"errors"
)

var ErrRemoteAgentUnavailable = errors.New("remote agent execution is disabled until authenticated job leasing is implemented")

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
	return ErrRemoteAgentUnavailable
}
