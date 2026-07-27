package scheduler

import (
	"context"
	"path/filepath"
	"testing"

	"enumscan/internal/models"
	"enumscan/internal/store"
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

type persistenceTestModule struct{ db *store.SQLiteCLI }

func (m persistenceTestModule) Name() string            { return "persistence_test" }
func (m persistenceTestModule) Subscriptions() []string { return []string{"test.persistence"} }
func (m persistenceTestModule) Handle(ctx context.Context, event models.Event) ([]models.Event, error) {
	return nil, m.db.AddAsset(ctx, models.Asset{ScanID: event.ScanID, Type: "persisted", Value: event.Target})
}

func TestConcurrentSchedulerPersistenceCompletes(t *testing.T) {
	db, err := store.OpenSQLiteCLI(filepath.Join(t.TempDir(), "scheduler.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	queue := New(4, 0, 0, 1000000000, nil)
	queue.Register(persistenceTestModule{db: db})
	for i := 0; i < 20; i++ {
		queue.Enqueue(models.Event{ScanID: "scheduler", Type: "test.persistence", Target: string(rune('a' + i))})
	}
	if err := queue.Run(ctx, db); err != nil {
		t.Fatalf("concurrent scheduler run failed: %v", err)
	}
	assets, err := db.Assets(ctx, "scheduler")
	if err != nil || len(assets) != 20 {
		t.Fatalf("assets=%d err=%v", len(assets), err)
	}
}
