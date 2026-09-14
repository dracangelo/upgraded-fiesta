package engine

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"enumscan/internal/models"
	"enumscan/internal/scheduler"
	"enumscan/internal/store"
)

// BenchmarkLargeScaleEventPipeline measures the storage, scheduling, bounded
// deduplication, and checkpoint path using a representative 1,000-target
// in-process engagement shape. It performs no network activity.
func BenchmarkLargeScaleEventPipeline(b *testing.B) {
	targetCount := 1000
	if raw := os.Getenv("ENUMSCAN_BENCH_TARGETS"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 100000 {
			b.Fatalf("ENUMSCAN_BENCH_TARGETS must be between 1 and 100000")
		}
		targetCount = parsed
	}
	db, err := store.OpenSQLiteCLI(filepath.Join(b.TempDir(), "pipeline.sqlite"))
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for iteration := 0; iteration < b.N; iteration++ {
		scanID := fmt.Sprintf("benchmark-%d", iteration)
		if err := db.StartScan(context.Background(), scanID); err != nil {
			b.Fatal(err)
		}
		queue := scheduler.New(16, 0, 0, 5*time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
		queue.Register(benchmarkSink{})
		for host := 0; host < targetCount; host++ {
			queue.Enqueue(models.Event{ScanID: scanID, Type: "benchmark.target", Target: fmt.Sprintf("10.99.%d.%d", host/256, host%256)})
		}
		if err := queue.Run(context.Background(), db); err != nil {
			b.Fatal(err)
		}
		if err := db.FinishScan(context.Background(), scanID, "completed", ""); err != nil {
			b.Fatal(err)
		}
	}
}

type benchmarkSink struct{}

func (benchmarkSink) Name() string                                                 { return "benchmark_sink" }
func (benchmarkSink) Subscriptions() []string                                      { return []string{"benchmark.target"} }
func (benchmarkSink) Handle(context.Context, models.Event) ([]models.Event, error) { return nil, nil }
