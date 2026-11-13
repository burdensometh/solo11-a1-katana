package hybrid

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/katana/pkg/engine/common"
	"github.com/projectdiscovery/katana/pkg/engine/parser"
	"github.com/projectdiscovery/katana/pkg/navigation"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/projectdiscovery/katana/pkg/utils/extensions"
	"github.com/projectdiscovery/katana/pkg/utils/queue"
	"github.com/projectdiscovery/katana/pkg/utils/scope"
	"github.com/stretchr/testify/require"
)

type statsTestWriter struct{}

func (statsTestWriter) Close() error                 { return nil }
func (statsTestWriter) Write(*output.Result) error   { return nil }
func (statsTestWriter) WriteErr(*output.Error) error { return nil }
func (statsTestWriter) GetResultCount() int64        { return 0 }

type allowAllFilter struct{}

func (allowAllFilter) Close()                      {}
func (allowAllFilter) UniqueContent(_ []byte) bool { return true }
func (allowAllFilter) IsCycle(_ string) bool       { return false }
func (allowAllFilter) UniqueURL(_ string) bool     { return true }

func newStatsTestCrawler(t *testing.T, maxDomainPages int) (*Crawler, *types.CrawlerOptions) {
	t.Helper()
	scopeManager, err := scope.NewManager(nil, nil, "", true)
	require.NoError(t, err)
	crawlerOpts := &types.CrawlerOptions{
		Options: &types.Options{
			MaxDepth:       10,
			Strategy:       "depth-first",
			MaxDomainPages: maxDomainPages,
		},
		OutputWriter:        statsTestWriter{},
		UniqueFilter:        allowAllFilter{},
		ScopeManager:        scopeManager,
		ExtensionsValidator: extensions.NewValidator(nil, nil, true),
		Parser:              parser.NewResponseParser(),
	}
	shared, err := common.NewShared(crawlerOpts)
	require.NoError(t, err)
	return &Crawler{Shared: shared}, crawlerOpts
}

func statsTestResponse(t *testing.T, req *navigation.Request, status int) *navigation.Response {
	t.Helper()
	parsed, err := url.Parse(req.URL)
	require.NoError(t, err)
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(`<html><body></body></html>`))
	require.NoError(t, err)
	return &navigation.Response{
		Resp:         &http.Response{StatusCode: status, Header: http.Header{}, Request: &http.Request{URL: parsed}},
		Reader:       doc,
		StatusCode:   status,
		Depth:        req.Depth + 1,
		RootHostname: "example.com",
	}
}

// Every enqueued request must land in exactly one crawl-stats bucket.
func TestVisitCrawlStatsOutcomes(t *testing.T) {
	crawler, crawlerOpts := newStatsTestCrawler(t, 0)

	q, err := queue.New("depth-first")
	require.NoError(t, err)
	session := &common.CrawlSession{Ctx: context.Background(), Queue: q, Hostname: "example.com"}

	crawler.Enqueue(q,
		&navigation.Request{Method: http.MethodGet, URL: "https://example.com/ok", Depth: 1, RootHostname: "example.com"},
		&navigation.Request{Method: http.MethodGet, URL: "https://example.com/redirect", Depth: 1, RootHostname: "example.com"},
		&navigation.Request{Method: http.MethodGet, URL: "https://example.com/fail", Depth: 1, RootHostname: "example.com"},
		&navigation.Request{Method: http.MethodGet, URL: "https://example.com/empty", Depth: 1, RootHostname: "example.com"},
	)

	doRequest := func(_ *common.CrawlSession, req *navigation.Request) (*navigation.Response, error) {
		switch req.URL {
		case "https://example.com/ok":
			return statsTestResponse(t, req, 200), nil
		case "https://example.com/redirect":
			return statsTestResponse(t, req, 302), nil
		case "https://example.com/fail":
			return nil, errors.New("connection refused")
		case "https://example.com/empty":
			return &navigation.Response{}, nil
		default:
			t.Errorf("unexpected fetch of %s", req.URL)
			return nil, errors.New("unexpected fetch")
		}
	}

	require.NoError(t, crawler.Do(session, doRequest))

	snap := crawlerOpts.Stats().Snapshot()
	require.Equal(t, int64(4), snap.Enqueued)
	require.Equal(t, int64(1), snap.Output, "/ok")
	require.Equal(t, int64(1), snap.Redirect, "/redirect")
	require.Equal(t, int64(2), snap.ParseFailed, "/fail and /empty")
	require.Equal(t, int64(0), snap.OutOfScope)
	require.Equal(t, snap.Enqueued, snap.Processed(),
		"output+redirect+parseFailed+outOfScope must equal enqueued")
}

// Requests dropped by the per-domain page budget are discarded, not fetched.
func TestVisitCrawlStatsDomainBudget(t *testing.T) {
	crawler, crawlerOpts := newStatsTestCrawler(t, 1)

	q, err := queue.New("depth-first")
	require.NoError(t, err)
	session := &common.CrawlSession{Ctx: context.Background(), Queue: q, Hostname: "example.com"}

	crawler.Enqueue(q,
		&navigation.Request{Method: http.MethodGet, URL: "https://example.com/a", Depth: 1, RootHostname: "example.com"},
		&navigation.Request{Method: http.MethodGet, URL: "https://example.com/b", Depth: 1, RootHostname: "example.com"},
	)

	fetched := 0
	doRequest := func(_ *common.CrawlSession, req *navigation.Request) (*navigation.Response, error) {
		fetched++
		return statsTestResponse(t, req, 200), nil
	}

	require.NoError(t, crawler.Do(session, doRequest))

	snap := crawlerOpts.Stats().Snapshot()
	require.Equal(t, int64(2), snap.Enqueued)
	require.Equal(t, int64(1), snap.Output, "only one page fits the budget")
	require.Equal(t, int64(1), snap.OutOfScope, "the other is discarded")
	require.Equal(t, 1, fetched)
	require.Equal(t, snap.Enqueued, snap.Processed())
}
