package sweep

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestRunPoolCollectsAllRecords(t *testing.T) {
	var tasks []Task
	for i := 0; i < 20; i++ {
		tasks = append(tasks, func(ctx context.Context) ([]Record, error) {
			return []Record{{Name: "r"}, {Name: "r"}}, nil
		})
	}
	records, err := RunPool(context.Background(), 4, tasks)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 40 {
		t.Fatalf("expected 40 records, got %d", len(records))
	}
}

func TestRunPoolBoundsConcurrency(t *testing.T) {
	var active, peak int64
	var tasks []Task
	for i := 0; i < 30; i++ {
		tasks = append(tasks, func(ctx context.Context) ([]Record, error) {
			cur := atomic.AddInt64(&active, 1)
			for {
				p := atomic.LoadInt64(&peak)
				if cur <= p || atomic.CompareAndSwapInt64(&peak, p, cur) {
					break
				}
			}
			atomic.AddInt64(&active, -1)
			return nil, nil
		})
	}
	if _, err := RunPool(context.Background(), 3, tasks); err != nil {
		t.Fatal(err)
	}
	if peak > 3 {
		t.Fatalf("worker pool exceeded bound: peak %d", peak)
	}
}

func TestRunPoolPropagatesError(t *testing.T) {
	boom := errors.New("boom")
	tasks := []Task{
		func(ctx context.Context) ([]Record, error) { return nil, boom },
		func(ctx context.Context) ([]Record, error) { return []Record{{}}, nil },
	}
	if _, err := RunPool(context.Background(), 2, tasks); !errors.Is(err, boom) {
		t.Fatalf("expected boom, got %v", err)
	}
}
