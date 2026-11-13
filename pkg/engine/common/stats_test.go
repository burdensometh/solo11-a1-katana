package common

import (
	"sync"
	"testing"

	"github.com/projectdiscovery/katana/pkg/utils/scope"
	"github.com/stretchr/testify/require"
)

func TestScopeStatsCounters(t *testing.T) {
	stats := NewScopeStats()

	stats.RecordAllowed("a.example")
	stats.RecordAllowed("a.example")
	stats.RecordBlocked("a.example", scope.ReasonOutOfBound)
	stats.RecordBlocked("a.example", scope.ReasonOutOfBound)
	stats.RecordBlocked("a.example", scope.ReasonPathFiltered)
	stats.RecordBlocked("a.example", scope.ReasonDepthExceeded)

	stats.RecordAllowed("b.example")
	stats.RecordBlocked("b.example", scope.ReasonOutOfBound)

	snaps := stats.Snapshot()
	require.Len(t, snaps, 2)
	// Snapshot must be ordered by target name.
	require.Equal(t, "a.example", snaps[0].target)
	require.Equal(t, "b.example", snaps[1].target)

	require.Equal(t, int64(2), snaps[0].allowed)
	require.Equal(t, int64(2), snaps[0].blocked[scope.ReasonOutOfBound])
	require.Equal(t, int64(1), snaps[0].blocked[scope.ReasonPathFiltered])
	require.Equal(t, int64(1), snaps[0].blocked[scope.ReasonDepthExceeded])

	require.Equal(t, int64(1), snaps[1].allowed)
	require.Equal(t, int64(1), snaps[1].blocked[scope.ReasonOutOfBound])
}

func TestScopeStatsEmptyTargetFallsBack(t *testing.T) {
	stats := NewScopeStats()
	stats.RecordBlocked("", scope.ReasonOutOfBound)

	snaps := stats.Snapshot()
	require.Len(t, snaps, 1)
	require.Equal(t, "unknown", snaps[0].target)
	require.Equal(t, int64(1), snaps[0].blocked[scope.ReasonOutOfBound])
}

func TestScopeStatsNilSafeAndAllowedIgnored(t *testing.T) {
	var stats *ScopeStats
	// Nil collector must not panic.
	stats.RecordAllowed("x")
	stats.RecordBlocked("x", scope.ReasonOutOfBound)
	require.Nil(t, stats.Snapshot())
	stats.Report()

	stats = NewScopeStats()
	// The allowed pseudo-reason must never be counted as a block and must not
	// even create a target entry.
	stats.RecordBlocked("x", scope.ReasonAllowed)
	require.Empty(t, stats.Snapshot())
}

func TestScopeStatsConcurrent(t *testing.T) {
	stats := NewScopeStats()

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				stats.RecordAllowed("target")
				stats.RecordBlocked("target", scope.ReasonOutOfBound)
				stats.RecordBlocked("target", scope.ReasonPathFiltered)
				stats.RecordBlocked("target", scope.ReasonDepthExceeded)
			}
		}()
	}
	wg.Wait()

	snaps := stats.Snapshot()
	require.Len(t, snaps, 1)
	require.Equal(t, int64(5000), snaps[0].allowed)
	require.Equal(t, int64(5000), snaps[0].blocked[scope.ReasonOutOfBound])
	require.Equal(t, int64(5000), snaps[0].blocked[scope.ReasonPathFiltered])
	require.Equal(t, int64(5000), snaps[0].blocked[scope.ReasonDepthExceeded])
}

func TestScopeStatsStartStopReports(t *testing.T) {
	stats := NewScopeStats()
	stats.RecordAllowed("target")
	stats.RecordBlocked("target", scope.ReasonDepthExceeded)

	// A zero interval disables ticking but stop must still emit the final
	// report without hanging.
	stop := stats.StartPeriodicReport(0)
	stop()
}
