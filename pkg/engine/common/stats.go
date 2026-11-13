package common

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/katana/pkg/utils/scope"
)

// targetStats holds per-target scope counters. All fields are atomics so the
// enqueue/accept hot paths can record decisions without taking locks.
type targetStats struct {
	// allowed counts URLs that passed every check and were enqueued.
	allowed atomic.Int64
	// blocked counts intercepted URLs keyed by the scope.Reason code.
	blocked map[scope.Reason]*atomic.Int64
}

func newTargetStats() *targetStats {
	ts := &targetStats{blocked: make(map[scope.Reason]*atomic.Int64, len(allReasons))}
	// Pre-allocate every known reason counter so the hot path only performs
	// atomic adds and never writes the map concurrently.
	for _, reason := range allReasons {
		ts.blocked[reason] = &atomic.Int64{}
	}
	return ts
}

func (t *targetStats) block(reason scope.Reason) {
	if counter, ok := t.blocked[reason]; ok {
		counter.Add(1)
	}
}

// snapshot is an immutable point-in-time copy of targetStats used for reporting.
type targetSnapshot struct {
	target  string
	allowed int64
	blocked map[scope.Reason]int64
}

// ScopeStats accumulates, per crawl target (root hostname), how many URLs were
// allowed through to the queue and how many were intercepted by each scope
// reason code. It is safe for concurrent use.
type ScopeStats struct {
	targets sync.Map // map[string]*targetStats
}

// NewScopeStats creates an empty ScopeStats collector.
func NewScopeStats() *ScopeStats {
	return &ScopeStats{}
}

func (s *ScopeStats) statsFor(target string) *targetStats {
	if target == "" {
		target = "unknown"
	}
	val, _ := s.targets.LoadOrStore(target, newTargetStats())
	return val.(*targetStats)
}

// RecordAllowed increments the allowed counter for a target.
func (s *ScopeStats) RecordAllowed(target string) {
	if s == nil {
		return
	}
	s.statsFor(target).allowed.Add(1)
}

// RecordBlocked increments the interception counter for the given reason on a
// target.
func (s *ScopeStats) RecordBlocked(target string, reason scope.Reason) {
	if s == nil || reason == scope.ReasonAllowed {
		return
	}
	s.statsFor(target).block(reason)
}

// Snapshot returns per-target counters ordered by target name.
func (s *ScopeStats) Snapshot() []targetSnapshot {
	if s == nil {
		return nil
	}
	snapshots := make([]targetSnapshot, 0)
	s.targets.Range(func(key, value any) bool {
		ts := value.(*targetStats)
		blocked := make(map[scope.Reason]int64, len(ts.blocked))
		for reason, counter := range ts.blocked {
			blocked[reason] = counter.Load()
		}
		snapshots = append(snapshots, targetSnapshot{
			target:  key.(string),
			allowed: ts.allowed.Load(),
			blocked: blocked,
		})
		return true
	})
	sort.Slice(snapshots, func(i, j int) bool { return snapshots[i].target < snapshots[j].target })
	return snapshots
}

// allReasons lists the reason codes in the order they are rendered in summary
// lines, so output stays stable across runs.
var allReasons = []scope.Reason{
	scope.ReasonOutOfBound,
	scope.ReasonPathFiltered,
	scope.ReasonDepthExceeded,
}

// Report writes one summary line per target with its allowed count and every
// non-zero interception counter. Targets with no activity are skipped. It
// writes to stderr directly (like the crawl progress stats) so the summary is
// not mixed into the result stream on stdout.
func (s *ScopeStats) Report() {
	if s == nil {
		return
	}
	for _, snap := range s.Snapshot() {
		var parts []string
		parts = append(parts, fmt.Sprintf("allowed=%d", snap.allowed))
		for _, reason := range allReasons {
			if count := snap.blocked[reason]; count > 0 {
				parts = append(parts, fmt.Sprintf("%s=%d", reason, count))
			}
		}
		fmt.Fprintf(os.Stderr, "Scope stats [%s]: %s\n", snap.target, strings.Join(parts, " "))
	}
}

// StartPeriodicReport emits a scope summary every interval until the returned
// stop function is called; stop also emits a final summary so short crawls are
// still reported. A non-positive interval disables the periodic ticker while
// keeping the final report on stop.
func (s *ScopeStats) StartPeriodicReport(interval time.Duration) (stop func()) {
	var (
		ticker  *time.Ticker
		quit    = make(chan struct{})
		stopped = make(chan struct{})
	)
	if interval > 0 {
		ticker = time.NewTicker(interval)
	}
	go func() {
		defer close(stopped)
		if ticker == nil {
			<-quit
			return
		}
		for {
			select {
			case <-ticker.C:
				s.Report()
			case <-quit:
				return
			}
		}
	}()
	return func() {
		if ticker != nil {
			ticker.Stop()
		}
		close(quit)
		<-stopped
		s.Report()
	}
}

// statsStopMu protects the lazy scope-stats ticker lifecycle below.
var statsStopMu sync.Mutex

// StartScopeStats starts the periodic scope summary using the configured
// StatsInterval (seconds), but only when ShowStatistics is enabled; otherwise
// it is a no-op and StopScopeStats is harmless. It is safe to call from
// concurrent per-target crawls: only the first call starts a ticker, and every
// call must be paired with StopScopeStats, which emits the final summary once
// the last caller leaves.
func (s *Shared) StartScopeStats() {
	if !s.Options.Options.ShowStatistics {
		return
	}
	interval := time.Duration(s.Options.Options.StatsInterval) * time.Second
	statsStopMu.Lock()
	defer statsStopMu.Unlock()
	if s.statsActive {
		s.statsWaiters++
		return
	}
	s.statsStop = s.ScopeStats.StartPeriodicReport(interval)
	s.statsActive = true
	s.statsWaiters = 1
}

// StopScopeStats decrements the periodic-report reference count and, when the
// last target finishes, stops the ticker and prints the final summary.
func (s *Shared) StopScopeStats() {
	statsStopMu.Lock()
	defer statsStopMu.Unlock()
	if !s.statsActive {
		return
	}
	s.statsWaiters--
	if s.statsWaiters > 0 {
		return
	}
	stop := s.statsStop
	s.statsStop = nil
	s.statsActive = false
	stop()
}
