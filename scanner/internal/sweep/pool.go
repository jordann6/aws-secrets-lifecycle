package sweep

import (
	"context"
	"sync"
)

// Task produces records for one (service, account, region) sweep.
type Task func(ctx context.Context) ([]Record, error)

// RunPool executes tasks with at most workers goroutines and collects
// every record. The first error cancels remaining work.
func RunPool(ctx context.Context, workers int, tasks []Task) ([]Record, error) {
	if workers < 1 {
		workers = 1
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	taskCh := make(chan Task)
	resultCh := make(chan []Record, len(tasks))
	errCh := make(chan error, len(tasks))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for task := range taskCh {
				recs, err := task(ctx)
				if err != nil {
					errCh <- err
					cancel()
					return
				}
				resultCh <- recs
			}
		}()
	}

	for _, t := range tasks {
		select {
		case taskCh <- t:
		case <-ctx.Done():
		}
	}
	close(taskCh)
	wg.Wait()
	close(resultCh)
	close(errCh)

	if err := <-errCh; err != nil {
		return nil, err
	}
	var all []Record
	for recs := range resultCh {
		all = append(all, recs...)
	}
	return all, nil
}
