// Package logstream is an in-memory pub/sub for recon-run logs, backing the SSE
// endpoint (ports.LogStream). Each run keeps a bounded replay buffer of recent
// lines so a reconnecting client (SSE Last-Event-ID) can resume without gaps, then
// tails live lines. It carries no business logic.
package logstream

import (
	"sync"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/usecase/ports"
)

const (
	defaultReplayCap = 500              // events retained per run for reconnect-replay
	subBuffer        = 1024             // per-subscriber channel buffer (> replayCap)
	streamTTL        = 15 * time.Minute // retain a closed stream this long for late reconnect-replay, then evict
)

// Broker implements ports.LogStream.
type Broker struct {
	mu        sync.Mutex
	runs      map[string]*runStream
	replayCap int
}

var _ ports.LogStream = (*Broker)(nil)

// NewBroker returns a broker retaining replayCap events per run (<=0 = default).
func NewBroker(replayCap int) *Broker {
	if replayCap <= 0 {
		replayCap = defaultReplayCap
	}
	return &Broker{runs: map[string]*runStream{}, replayCap: replayCap}
}

type runStream struct {
	mu       sync.Mutex
	seq      int
	buf      []ports.LogEvent
	subs     map[int]chan ports.LogEvent
	nextSub  int
	closed   bool
	closedAt time.Time
}

func (b *Broker) stream(runID string) *runStream {
	b.mu.Lock()
	defer b.mu.Unlock()
	rs := b.runs[runID]
	if rs == nil {
		rs = &runStream{subs: map[int]chan ports.LogEvent{}}
		b.runs[runID] = rs
	}
	return rs
}

// Publish appends a line to the run's stream and fans it out to live subscribers.
// A subscriber whose buffer is full is skipped for this live event (it remains in
// the replay buffer, so a reconnect recovers it) – the publisher never blocks.
func (b *Broker) Publish(runID, line string) {
	rs := b.stream(runID)
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.closed {
		return
	}
	rs.seq++
	e := ports.LogEvent{ID: rs.seq, Line: line}
	rs.buf = append(rs.buf, e)
	if len(rs.buf) > b.replayCap {
		rs.buf = rs.buf[len(rs.buf)-b.replayCap:]
	}
	for _, ch := range rs.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Close marks the run's stream ended: it emits a final Done event and closes every
// subscriber channel (so SSE handlers terminate). The replay buffer is kept so a
// late reconnect still gets the history + Done.
func (b *Broker) Close(runID string) {
	rs := b.stream(runID)
	rs.mu.Lock()
	if rs.closed {
		rs.mu.Unlock()
		return
	}
	rs.closed = true
	rs.closedAt = time.Now()
	rs.seq++
	done := ports.LogEvent{ID: rs.seq, Done: true}
	for id, ch := range rs.subs {
		select {
		case ch <- done:
		default:
		}
		close(ch)
		delete(rs.subs, id)
	}
	rs.mu.Unlock()
	b.evictExpired() // bound memory: drop long-closed streams (history is in the run store)
}

// evictExpired removes streams that closed more than streamTTL ago and have no live
// subscribers. Lock order is always b.mu -> rs.mu (only acquired together here).
func (b *Broker) evictExpired() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, rs := range b.runs {
		rs.mu.Lock()
		expired := rs.closed && len(rs.subs) == 0 && time.Since(rs.closedAt) > streamTTL
		rs.mu.Unlock()
		if expired {
			delete(b.runs, id)
		}
	}
}

// Subscribe replays buffered events with ID > afterID, then (if the stream is still
// open) registers for live events. The cancel func unsubscribes. If the stream is
// already closed, the returned channel carries the replay + a Done and is closed.
func (b *Broker) Subscribe(runID string, afterID int) (<-chan ports.LogEvent, func()) {
	rs := b.stream(runID)
	rs.mu.Lock()
	defer rs.mu.Unlock()

	ch := make(chan ports.LogEvent, subBuffer)
	for _, e := range rs.buf {
		if e.ID > afterID {
			ch <- e // safe: len(buf) <= replayCap < subBuffer
		}
	}
	if rs.closed {
		ch <- ports.LogEvent{ID: rs.seq, Done: true}
		close(ch)
		return ch, func() {}
	}
	id := rs.nextSub
	rs.nextSub++
	rs.subs[id] = ch
	cancel := func() {
		rs.mu.Lock()
		defer rs.mu.Unlock()
		if c, ok := rs.subs[id]; ok {
			delete(rs.subs, id)
			close(c)
		}
	}
	return ch, cancel
}
