// Package targetlimit allocates crawling concurrency per target.
//
// A crawl that shares one concurrency budget across every target lets a single
// slow target occupy all worker slots while the remaining targets sit idle in
// the queue: the crawl becomes slower than a serial one. The limiter here
// gives every target its own bucket of concurrent request slots, so a target
// can only starve itself, plus one process-wide ceiling on the sum of all
// buckets so that a long target list cannot oversubscribe the machine.
//
// Buckets are adaptive. Every timeout halves the target's current budget
// (never below one slot); the next successful request ends the timeout streak
// and a recovery ticker then returns one slot per RecoveryInterval until the
// initial budget is restored.
package targetlimit

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultPerTarget is the initial number of concurrent request slots
	// handed to every target.
	DefaultPerTarget = 4
	// DefaultParallelism mirrors the crawler's default -parallelism value. It
	// is only used to derive a global ceiling when Global is not configured.
	DefaultParallelism = 10
	// DefaultRecoveryInterval is how long a recovering target waits between
	// two recovered slots.
	DefaultRecoveryInterval = time.Second

	minPerTarget = 1
)

// ErrClosed is returned by Acquire once the limiter has been closed.
var ErrClosed = errors.New("target limiter is closed")

// Options configures a Limiter. Zero values select the documented defaults.
type Options struct {
	// PerTarget is the initial number of concurrency slots per target.
	PerTarget int
	// Parallelism is the default number of targets processed at once, used to
	// derive Global when it is not configured. Zero uses DefaultParallelism.
	Parallelism int
	// Global is the maximum number of concurrent slots across all targets.
	// Zero derives PerTarget * Parallelism.
	Global int
	// RecoveryInterval is the delay between two recovered slots of the same
	// target. Zero uses DefaultRecoveryInterval.
	RecoveryInterval time.Duration
}

// Limiter allocates concurrency slots per target under a global ceiling.
// It is safe for concurrent use.
type Limiter struct {
	opts Options

	mu      sync.Mutex
	buckets map[string]*bucket
	closed  bool

	global chan struct{}
	done   chan struct{}

	closeOnce    sync.Once
	recoveryOnce sync.Once
	recoveryWG   sync.WaitGroup
}

// bucket holds the slots of one target. The limit is the adaptive budget;
// inflight counts acquired slots. Waiters are notified whenever a slot may
// have become available.
type bucket struct {
	mu sync.Mutex
	// inflight is the number of acquired slots.
	inflight int
	// limit is the adaptive concurrency budget of the target.
	limit int
	// capacity is the initial budget restored after recovery.
	capacity int
	// recovering is set after a successful request following a timeout. The
	// recovery ticker adds one slot per interval until capacity is reached.
	recovering bool
	waiters    map[*waiter]struct{}
}

type waiter struct {
	ch chan struct{}
}

// New creates a Limiter. The recovery goroutine starts with the first
// timeout lowered bucket and stops on Close.
func New(opts Options) *Limiter {
	if opts.PerTarget <= 0 {
		opts.PerTarget = DefaultPerTarget
	}
	if opts.Parallelism <= 0 {
		opts.Parallelism = DefaultParallelism
	}
	if opts.Global <= 0 {
		opts.Global = opts.PerTarget * opts.Parallelism
	}
	if opts.Global < opts.PerTarget {
		// A global ceiling below one target's initial budget would make that
		// budget unreachable. Keep at least one target fully served.
		opts.Global = opts.PerTarget
	}
	if opts.RecoveryInterval <= 0 {
		opts.RecoveryInterval = DefaultRecoveryInterval
	}

	l := &Limiter{
		opts:    opts,
		buckets: make(map[string]*bucket),
		global:  make(chan struct{}, opts.Global),
		done:    make(chan struct{}),
	}
	for i := 0; i < opts.Global; i++ {
		l.global <- struct{}{}
	}
	return l
}

// PerTarget returns the initial budget per target.
func (l *Limiter) PerTarget() int { return l.opts.PerTarget }

// GlobalLimit returns the process-wide concurrency ceiling.
func (l *Limiter) GlobalLimit() int { return l.opts.Global }

// Acquire reserves one concurrency slot for target. It first claims a
// target-local slot and then a global one; the returned release function
// returns both and is safe to call more than once. Acquire blocks while either
// budget is exhausted and returns the context's error (or ErrClosed) when the
// crawl ends first.
func (l *Limiter) Acquire(ctx context.Context, target string) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-l.done:
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	default:
	}

	b := l.bucketFor(target)
	if err := b.acquire(ctx, l.done); err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		b.release()
		return nil, context.Cause(ctx)
	case <-l.done:
		b.release()
		return nil, ErrClosed
	case <-l.global:
	}

	// Acquisition may have raced with Close: both budgets were granted, but
	// the crawl is ending. Put them back and report closure.
	select {
	case <-l.done:
		l.putGlobal()
		b.release()
		return nil, ErrClosed
	default:
	}

	var once sync.Once
	release := func() {
		once.Do(func() {
			l.putGlobal()
			b.release()
		})
	}
	return release, nil
}

// RecordTimeout lowers the target's budget. Every timeout halves the current
// budget (4 -> 2 -> 1) so a timeout can never raise it, and the budget never
// drops below one slot. Recovery pauses until a request succeeds again.
func (l *Limiter) RecordTimeout(target string) {
	b := l.bucketFor(target)
	b.mu.Lock()
	b.recovering = false
	if b.limit > minPerTarget {
		b.limit /= 2
		if b.limit < minPerTarget {
			b.limit = minPerTarget
		}
	}
	b.mu.Unlock()
}

// RecordSuccess ends the target's timeout streak. When timeouts had lowered
// the budget, it starts returning one slot per RecoveryInterval up to the
// initial budget.
func (l *Limiter) RecordSuccess(target string) {
	b := l.bucketFor(target)
	b.mu.Lock()
	start := b.limit < b.capacity
	b.recovering = start
	b.mu.Unlock()
	if start {
		l.startRecovery()
	}
}

// Limit reports the current adaptive concurrency budget for target. Targets
// that were never used report the initial budget.
func (l *Limiter) Limit(target string) int {
	if b := l.peekBucket(target); b != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.limit
	}
	return l.opts.PerTarget
}

// InFlight reports how many slots of target are currently held.
func (l *Limiter) InFlight(target string) int {
	if b := l.peekBucket(target); b != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
		return b.inflight
	}
	return 0
}

// Close stops the recovery ticker and unblocks every waiter. Acquire returns
// ErrClosed afterwards. Close is idempotent.
func (l *Limiter) Close() {
	l.closeOnce.Do(func() {
		l.mu.Lock()
		l.closed = true
		close(l.done)
		l.mu.Unlock()
		l.recoveryWG.Wait()
	})
}

func targetKey(target string) string {
	return strings.ToLower(strings.TrimSpace(target))
}

// bucketFor returns the bucket of target, creating it on first use.
func (l *Limiter) bucketFor(target string) *bucket {
	key := targetKey(target)
	l.mu.Lock()
	defer l.mu.Unlock()
	if b, ok := l.buckets[key]; ok {
		return b
	}
	b := newBucket(l.opts.PerTarget)
	l.buckets[key] = b
	return b
}

func (l *Limiter) peekBucket(target string) *bucket {
	key := targetKey(target)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buckets[key]
}

func (l *Limiter) putGlobal() {
	select {
	case l.global <- struct{}{}:
	default:
	}
}

// startRecovery launches the single recovery goroutine once per limiter. It
// registers with the waitgroup under the limiter lock so Close cannot begin
// waiting between the check and the Add.
func (l *Limiter) startRecovery() {
	l.recoveryOnce.Do(func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.closed {
			return
		}
		l.recoveryWG.Add(1)
		go l.recoverLoop()
	})
}

func (l *Limiter) recoverLoop() {
	defer l.recoveryWG.Done()
	ticker := time.NewTicker(l.opts.RecoveryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-ticker.C:
			l.recoverTick()
		}
	}
}

// recoverTick adds one slot to every recovering bucket that is still below
// capacity.
func (l *Limiter) recoverTick() {
	l.mu.Lock()
	buckets := make([]*bucket, 0, len(l.buckets))
	for _, b := range l.buckets {
		buckets = append(buckets, b)
	}
	l.mu.Unlock()

	for _, b := range buckets {
		b.mu.Lock()
		if b.recovering && b.limit < b.capacity {
			b.limit++
			if b.limit >= b.capacity {
				b.recovering = false
			}
			b.wakeAllLocked()
		}
		b.mu.Unlock()
	}
}

func newBucket(capacity int) *bucket {
	return &bucket{
		limit:    capacity,
		capacity: capacity,
		waiters:  make(map[*waiter]struct{}),
	}
}

// acquire claims one slot of the bucket, blocking until one is free.
func (b *bucket) acquire(ctx context.Context, closed <-chan struct{}) error {
	for {
		b.mu.Lock()
		if b.inflight < b.limit {
			b.inflight++
			b.mu.Unlock()
			return nil
		}
		w := &waiter{ch: make(chan struct{}, 1)}
		b.waiters[w] = struct{}{}
		b.mu.Unlock()

		select {
		case <-ctx.Done():
			b.mu.Lock()
			delete(b.waiters, w)
			b.mu.Unlock()
			return context.Cause(ctx)
		case <-closed:
			b.mu.Lock()
			delete(b.waiters, w)
			b.mu.Unlock()
			return ErrClosed
		case <-w.ch:
			// Another waiter may have claimed the slot first; loop and retry.
		}
	}
}

// release returns one slot and wakes waiters if the freed slot is within the
// current budget. Slots released after a downscale stay dropped until the
// budget recovers.
func (b *bucket) release() {
	b.mu.Lock()
	if b.inflight > 0 {
		b.inflight--
	}
	if b.inflight < b.limit {
		b.wakeAllLocked()
	}
	b.mu.Unlock()
}

func (b *bucket) wakeAllLocked() {
	for w := range b.waiters {
		select {
		case w.ch <- struct{}{}:
		default:
		}
		delete(b.waiters, w)
	}
}

// IsTimeoutError reports whether err was caused by a request timing out rather
// than by a protocol or connection failure. Cancellation of the surrounding
// crawl context (context.Canceled) is not a target timeout. errkit wrappers
// (used by the engines) expose the underlying cause via Unwrap() []error, so
// errors.Is and errors.As both see through them.
func IsTimeoutError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
