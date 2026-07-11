// Package jobs is a small bounded worker pool: a fixed number of workers draining a
// fixed-size queue. It replaces the earlier "one bare goroutine per scan" with a
// real concurrency cap + backpressure, and is generic infrastructure –
// no business logic.
package jobs

import (
	"context"
	"errors"
	"sync"
)

// ErrQueueFull is returned by Submit when the queue is at capacity (backpressure –
// the caller should surface a "try again" rather than spawn unbounded work).
var ErrQueueFull = errors.New("job queue is full")

// ErrStopped is returned by Submit after the pool has been shut down.
var ErrStopped = errors.New("job pool is stopped")

// Task is a unit of work. It receives the pool's context, which is cancelled on
// Shutdown so in-flight work can stop promptly. It is an alias for the bare func
// type so callers can depend on a minimal `Submit(func(context.Context)) error`
// interface without importing this package.
type Task = func(ctx context.Context)

// Pool runs Tasks on a bounded set of workers.
type Pool struct {
	tasks  chan Task
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	stopped bool
}

// NewPool starts a pool with the given worker count and queue capacity (both
// floored at 1).
func NewPool(workers, queueSize int) *Pool {
	if workers < 1 {
		workers = 1
	}
	if queueSize < 1 {
		queueSize = 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Pool{tasks: make(chan Task, queueSize), ctx: ctx, cancel: cancel}
	p.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go p.worker()
	}
	return p
}

func (p *Pool) worker() {
	defer p.wg.Done()
	for task := range p.tasks {
		task(p.ctx)
	}
}

// Submit enqueues a task without blocking. It returns ErrQueueFull if the queue is
// at capacity, or ErrStopped after Shutdown. The non-blocking send happens UNDER the
// lock so it is mutually exclusive with Shutdown's close(p.tasks) – otherwise a
// Submit racing a Shutdown could send on a closed channel and panic.
func (p *Pool) Submit(t Task) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return ErrStopped
	}
	select {
	case p.tasks <- t:
		return nil
	default:
		return ErrQueueFull
	}
}

// Shutdown stops accepting tasks, cancels the pool context (signalling in-flight
// tasks), and waits for workers to drain – or until ctx is done, whichever first.
func (p *Pool) Shutdown(ctx context.Context) {
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped = true
	close(p.tasks)
	p.mu.Unlock()

	p.cancel()
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
