package types

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCrawlStatsInvariant(t *testing.T) {
	stats := &CrawlStats{}

	// four enqueued requests, each ending in a different bucket
	for range 4 {
		stats.IncEnqueued()
	}
	stats.IncOutput()
	stats.IncRedirect()
	stats.IncParseFailed()
	stats.IncOutOfScope()

	snap := stats.Snapshot()
	require.Equal(t, int64(4), snap.Enqueued)
	require.Equal(t, int64(1), snap.Output)
	require.Equal(t, int64(1), snap.Redirect)
	require.Equal(t, int64(1), snap.ParseFailed)
	require.Equal(t, int64(1), snap.OutOfScope)
	require.Equal(t, snap.Enqueued, snap.Processed(),
		"output+redirect+parseFailed+outOfScope must equal enqueued")
}

func TestCrawlStatsConcurrent(t *testing.T) {
	stats := &CrawlStats{}
	const workers = 8
	const perWorker = 1000

	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perWorker {
				stats.IncEnqueued()
				stats.IncOutput()
			}
		}()
	}
	wg.Wait()

	snap := stats.Snapshot()
	require.Equal(t, int64(workers*perWorker), snap.Enqueued)
	require.Equal(t, int64(workers*perWorker), snap.Output)
	require.Equal(t, snap.Enqueued, snap.Processed())
}

func TestCrawlerOptionsStatsLazyInit(t *testing.T) {
	// manually constructed options (no NewCrawlerOptions) must still work
	opts := &CrawlerOptions{}
	opts.Stats().IncEnqueued()
	require.Equal(t, int64(1), opts.Stats().Snapshot().Enqueued)
	// same instance returned every time
	require.Same(t, opts.Stats(), opts.Stats())
}
