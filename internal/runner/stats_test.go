package runner

import (
	"testing"
	"time"

	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestStatsLine(t *testing.T) {
	start := time.Date(2026, 11, 3, 13, 0, 0, 0, time.UTC)
	stats := types.CrawlStatsSnapshot{Enqueued: 150, Output: 120, Redirect: 10, ParseFailed: 5, OutOfScope: 15}
	require.Equal(t, "[2026-11-03 14:01:05] [1:01:05] | Inputs: 1/3 (33%) | Enqueued: 150 | Output: 120 | Redirects: 10 | Failed: 5 | Discarded: 15 | Endpoints: 130",
		statsLine(start.Add(time.Hour+65*time.Second), start, 1, 3, stats, 130))
	require.Equal(t, "[2026-11-03 13:00:00] [0:00:00] | Inputs: 0/0 (0%) | Enqueued: 0 | Output: 0 | Redirects: 0 | Failed: 0 | Discarded: 0 | Endpoints: 0",
		statsLine(start, start, 0, 0, types.CrawlStatsSnapshot{}, 0))
}
