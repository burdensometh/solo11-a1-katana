package types

import "sync/atomic"

// CrawlStats accounts for the fate of every request enqueued during a crawl.
//
// Every enqueued request ends in exactly one of the four outcome buckets, so
// once a crawl runs to completion the invariant is:
//
//	Output + Redirect + ParseFailed + OutOfScope == Enqueued
//
// A crawl interrupted by cancellation (timeout, Ctrl-C) leaves unprocessed
// items in the queue; those are counted in Enqueued but in no outcome bucket,
// so the buckets then sum to less than Enqueued by exactly the leftover count.
type CrawlStats struct {
	enqueued    atomic.Int64
	output      atomic.Int64
	redirect    atomic.Int64
	parseFailed atomic.Int64
	outOfScope  atomic.Int64
}

// IncEnqueued counts a request pushed into the crawl queue.
func (s *CrawlStats) IncEnqueued() { s.enqueued.Add(1) }

// IncOutput counts an enqueued request that was fetched and written to output.
func (s *CrawlStats) IncOutput() { s.output.Add(1) }

// IncRedirect counts an enqueued request whose final response was an HTTP redirect.
func (s *CrawlStats) IncRedirect() { s.redirect.Add(1) }

// IncParseFailed counts an enqueued request that failed or whose response
// could not be parsed (empty or filtered responses included).
func (s *CrawlStats) IncParseFailed() { s.parseFailed.Add(1) }

// IncOutOfScope counts an enqueued request discarded without being fetched:
// out of scope, filtered path, invalid URL, or over the per-domain page budget.
func (s *CrawlStats) IncOutOfScope() { s.outOfScope.Add(1) }

// CrawlStatsSnapshot is a point-in-time read of the crawl outcome counters.
type CrawlStatsSnapshot struct {
	// Enqueued is the total number of requests pushed into the crawl queue.
	Enqueued int64
	// Output is the number of requests fetched and written to output.
	Output int64
	// Redirect is the number of requests whose final response was a redirect.
	Redirect int64
	// ParseFailed is the number of requests that failed or could not be parsed.
	ParseFailed int64
	// OutOfScope is the number of enqueued requests discarded without fetching.
	OutOfScope int64
}

// Snapshot reads all counters.
func (s *CrawlStats) Snapshot() CrawlStatsSnapshot {
	return CrawlStatsSnapshot{
		Enqueued:    s.enqueued.Load(),
		Output:      s.output.Load(),
		Redirect:    s.redirect.Load(),
		ParseFailed: s.parseFailed.Load(),
		OutOfScope:  s.outOfScope.Load(),
	}
}

// Processed is the number of enqueued requests that reached a final outcome.
// After a crawl runs to completion, Processed == Enqueued.
func (s CrawlStatsSnapshot) Processed() int64 {
	return s.Output + s.Redirect + s.ParseFailed + s.OutOfScope
}
