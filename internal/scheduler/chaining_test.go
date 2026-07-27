package scheduler

import (
	"context"
	"testing"

	"enumscan/internal/models"
)

type chainTestModule struct {
	name          string
	subscriptions []string
}

func (m chainTestModule) Name() string            { return m.name }
func (m chainTestModule) Subscriptions() []string { return m.subscriptions }
func (m chainTestModule) Handle(context.Context, models.Event) ([]models.Event, error) {
	return nil, nil
}

func TestChainForListsEventConsumers(t *testing.T) {
	s := New(1, 0, 0, 0, nil)
	s.Register(chainTestModule{name: "one", subscriptions: []string{"host"}})
	s.Register(chainTestModule{name: "two", subscriptions: []string{"host"}})
	if got := s.ChainFor("host"); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("unexpected chain %#v", got)
	}
}
