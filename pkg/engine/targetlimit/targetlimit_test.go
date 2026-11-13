package targetlimit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func testLimiter(t *testing.T, opts Options) *Limiter {
	t.Helper()
	l := New(opts)
	t.Cleanup(l.Close)
	return l
}

func acquire(t *testing.T, l *Limiter, target string) func() {
	t.Helper()
	release, err := l.Acquire(context.Background(), target)
	require.NoError(t, err)
	return release
}

func TestDefaultPerTargetIsFour(t *testing.T) {
	l := testLimiter(t, Options{})
	require.Equal(t, 4, l.PerTarget())
	require.Equal(t, 4, l.Limit("example.com"))
}

func TestAcquireBoundsEachTargetIndependently(t *testing.T) {
	l := testLimiter(t, Options{PerTarget: 4, Global: 100})

	var releases []func()
	for i := 0; i < 4; i++ {
		releases = append(releases, acquire(t, l, "slow.example"))
	}
	require.Equal(t, 4, l.InFlight("slow.example"))

	// The slow target is at its budget, but another target still gets its own.
	fast := acquire(t, l, "fast.example")
	require.Equal(t, 1, l.InFlight("fast.example"))

	for _, release := range releases {
		release()
	}
	fast()
	require.Equal(t, 0, l.InFlight("slow.example"))
}

func TestAcquireBlocksAtTargetBudget(t *testing.T) {
	l := testLimiter(t, Options{PerTarget: 2, Global: 10})
	acquire(t, l, "a")
	acquire(t, l, "a")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := l.Acquire(ctx, "a")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestTargetBudgetIsCaseInsensitive(t *testing.T) {
	l := testLimiter(t, Options{PerTarget: 1, Global: 10})
	release := acquire(t, l, "Example.COM:443")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := l.Acquire(ctx, "example.com:443")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	release()
}

func TestGlobalCeilingLimitsSumOfTargets(t *testing.T) {
	l := testLimiter(t, Options{PerTarget: 4, Global: 5})

	// Fill the global ceiling from two targets: 4 slots of a, 1 of b.
	for i := 0; i < 4; i++ {
		acquire(t, l, "a")
	}
	acquire(t, l, "b")
	require.Equal(t, 4, l.InFlight("a"))
	require.Equal(t, 1, l.InFlight("b"))

	// Both targets have local budget left, but the shared ceiling is full.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := l.Acquire(ctx, "b")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestGlobalCeilingCapsBelowPerTarget(t *testing.T) {
	// A global ceiling smaller than the per-target budget must not make the
	// target budget unreachable.
	l := testLimiter(t, Options{PerTarget: 4, Global: 2})
	require.Equal(t, 4, l.GlobalLimit())
}

func TestConsecutiveTimeoutsHalveBudget(t *testing.T) {
	l := testLimiter(t, Options{PerTarget: 4, Global: 32})
	const target = "slow"

	require.Equal(t, 4, l.Limit(target))
	l.RecordTimeout(target)
	require.Equal(t, 2, l.Limit(target))
	l.RecordTimeout(target)
	require.Equal(t, 1, l.Limit(target))
	l.RecordTimeout(target)
	require.Equal(t, 1, l.Limit(target), "budget never drops below one slot")
}

func TestTimeoutDownscaleLimitsInFlightRequests(t *testing.T) {
	l := testLimiter(t, Options{PerTarget: 4, Global: 32})
	releases := []func(){acquire(t, l, "t"), acquire(t, l, "t")}

	l.RecordTimeout("t") // budget 2, both slots still held
	require.Equal(t, 2, l.Limit("t"))

	// Released slots stay dropped: the old budget is not restored by release.
	for _, release := range releases {
		release()
	}
	require.Equal(t, 0, l.InFlight("t"))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	first := acquire(t, l, "t")
	second := acquire(t, l, "t")
	_, err := l.Acquire(ctx, "t")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	first()
	second()
}

func TestSuccessStartsOneSlotPerSecondRecovery(t *testing.T) {
	l := New(Options{PerTarget: 4, Global: 32, RecoveryInterval: 20 * time.Millisecond})
	t.Cleanup(l.Close)

	l.RecordTimeout("t")
	l.RecordTimeout("t")
	require.Equal(t, 1, l.Limit("t"))

	l.RecordSuccess("t")
	require.Eventually(t, func() bool { return l.Limit("t") >= 2 }, time.Second, 5*time.Millisecond)
	require.Eventually(t, func() bool { return l.Limit("t") == 4 }, time.Second, 5*time.Millisecond)

	// Recovery stops at the initial budget.
	time.Sleep(5 * 20 * time.Millisecond)
	require.Equal(t, 4, l.Limit("t"))
}

func TestTimeoutsDuringRecoveryPauseIt(t *testing.T) {
	l := New(Options{PerTarget: 4, Global: 32, RecoveryInterval: 20 * time.Millisecond})
	t.Cleanup(l.Close)

	l.RecordTimeout("t") // 2
	l.RecordSuccess("t") // recovering
	l.RecordTimeout("t") // 1, recovery paused
	recovered := l.Limit("t")
	time.Sleep(5 * 20 * time.Millisecond)
	require.Equal(t, recovered, l.Limit("t"), "recovery must not proceed while the target keeps timing out")
}

func TestRecordSuccessWithoutTimeoutsDoesNotRecoverAboveCapacity(t *testing.T) {
	l := testLimiter(t, Options{PerTarget: 4, Global: 32})
	l.RecordSuccess("t")
	require.Equal(t, 4, l.Limit("t"))
}

func TestCloseUnblocksWaiters(t *testing.T) {
	l := New(Options{PerTarget: 1, Global: 1})
	release := acquire(t, l, "t")

	done := make(chan error, 1)
	go func() {
		_, err := l.Acquire(context.Background(), "t")
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)

	l.Close()
	select {
	case err := <-done:
		require.ErrorIs(t, err, ErrClosed)
	case <-time.After(time.Second):
		t.Fatal("close did not unblock a waiter")
	}
	release()

	_, err := l.Acquire(context.Background(), "t")
	require.ErrorIs(t, err, ErrClosed)
}

func TestContextCancelUnblocksWaiter(t *testing.T) {
	l := testLimiter(t, Options{PerTarget: 1, Global: 1})
	acquire(t, l, "t")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := l.Acquire(ctx, "t")
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not unblock a waiter")
	}
}

// TestSlowTargetDoesNotStarveOthers is the regression test for the reported
// problem: while many workers of one target are stuck on slow requests, a
// healthy target must still get its own full budget of slots.
func TestSlowTargetDoesNotStarveOthers(t *testing.T) {
	const perTarget = 4
	l := testLimiter(t, Options{PerTarget: perTarget, Global: 8})

	// Saturate the slow target.
	var slowReleases []func()
	var wg sync.WaitGroup
	for i := 0; i < perTarget; i++ {
		slowReleases = append(slowReleases, acquire(t, l, "slow"))
	}
	defer func() {
		for _, release := range slowReleases {
			release()
		}
	}()

	// Every request for the healthy target can proceed concurrently.
	var inflight atomic.Int64
	var maxInflight atomic.Int64
	for i := 0; i < perTarget; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := l.Acquire(context.Background(), "fast")
			if err != nil {
				return
			}
			defer release()
			now := inflight.Add(1)
			for {
				old := maxInflight.Load()
				if now <= old || maxInflight.CompareAndSwap(old, now) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			inflight.Add(-1)
		}()
	}
	wg.Wait()
	require.Equal(t, int64(perTarget), maxInflight.Load(), "healthy target was starved by the slow one")
}

func TestIsTimeoutError(t *testing.T) {
	require.False(t, IsTimeoutError(nil))
	require.True(t, IsTimeoutError(context.DeadlineExceeded))
	require.False(t, IsTimeoutError(context.Canceled))
	require.True(t, IsTimeoutError(fmt.Errorf("giving up: %w", context.DeadlineExceeded)))
	require.True(t, IsTimeoutError(&net.OpError{Op: "read", Err: &timeoutErr{}}))
	require.False(t, IsTimeoutError(errors.New("connection refused")))
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
