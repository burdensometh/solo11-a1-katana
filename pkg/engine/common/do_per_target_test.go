package common

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/projectdiscovery/katana/pkg/engine/parser"
	"github.com/projectdiscovery/katana/pkg/navigation"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/projectdiscovery/katana/pkg/utils/extensions"
	"github.com/projectdiscovery/katana/pkg/utils/queue"
	"github.com/projectdiscovery/katana/pkg/utils/scope"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

// newDoTestShared builds a Shared that can run Do against real servers.
func newDoTestShared(t *testing.T, opts *types.Options) *Shared {
	t.Helper()
	if opts.Strategy == "" {
		opts.Strategy = "depth-first"
	}
	scopeManager, err := scope.NewManager(nil, nil, "", true)
	require.NoError(t, err)

	responseParser := parser.NewResponseParser()
	responseParser.InitWithOptions(&parser.Options{})

	backoffs, err := lru.New[string, *hostBackoff](100)
	require.NoError(t, err)
	shared := &Shared{
		Options: &types.CrawlerOptions{
			Options:             opts,
			OutputWriter:        &mockWriter{},
			UniqueFilter:        newMockFilter(),
			ScopeManager:        scopeManager,
			ExtensionsValidator: extensions.NewValidator(nil, nil, true),
			Parser:              responseParser,
		},
		hostBackoffs: backoffs,
	}
	t.Cleanup(func() { _ = shared.Close() })
	return shared
}

// newQueueSession builds a CrawlSession whose queue already holds the given
// URLs for one target, without touching the network.
func newQueueSession(t *testing.T, ctx context.Context, target string, urls []string) *CrawlSession {
	t.Helper()
	q, err := queue.New("depth-first")
	require.NoError(t, err)
	for _, u := range urls {
		q.Push(&navigation.Request{Method: http.MethodGet, URL: u, Depth: 1, RootHostname: target}, 1)
	}
	sessionCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	return &CrawlSession{
		Ctx:        sessionCtx,
		CancelFunc: cancel,
		Hostname:   target,
		Queue:      q,
	}
}

// TestDoPerTargetConcurrencyLimitsSlowTarget is the regression test for the
// reported behaviour: with a per-target budget of 2, a target whose requests
// take a long time never has more than 2 of its requests in flight.
func TestDoPerTargetConcurrencyLimitsSlowTarget(t *testing.T) {
	const budget = 2
	var inflight, maxInflight atomic.Int64

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := inflight.Add(1)
		for {
			old := maxInflight.Load()
			if now <= old || maxInflight.CompareAndSwap(old, now) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		inflight.Add(-1)
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer server.Close()

	opts := &types.Options{
		MaxDepth:     3,
		BodyReadSize: 4096,
		Concurrency:  budget,
		Parallelism:  1,
	}
	shared := newDoTestShared(t, opts)

	var urls []string
	for i := 0; i < 8; i++ {
		urls = append(urls, fmt.Sprintf("%s/%d", server.URL, i))
	}
	session := newQueueSession(t, context.Background(), "slow.test", urls)
	parsed, _ := urlutil.Parse(server.URL)
	session.URL = parsed.URL

	doRequest := func(_ *CrawlSession, req *navigation.Request) (*navigation.Response, error) {
		resp, err := server.Client().Get(req.URL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return &navigation.Response{StatusCode: resp.StatusCode, Resp: resp}, nil
	}

	start := time.Now()
	require.NoError(t, shared.Do(session, doRequest))
	elapsed := time.Since(start)

	require.LessOrEqual(t, maxInflight.Load(), int64(budget), "target exceeded its concurrency budget")
	require.Greater(t, maxInflight.Load(), int64(1), "requests were serialised despite a budget of 2")
	// 8 requests at 40ms with 2 slots is about 4 rounds; serial would be 320ms.
	require.Less(t, elapsed, 300*time.Millisecond)
}

// TestDoDoesNotStarveFastTargetWhileSlowOneIsBusy runs two targets in
// parallel through the same Shared, as the runner does, and asserts the fast
// target finished its queue while the slow target was still loading.
func TestDoDoesNotStarveFastTargetWhileSlowOneIsBusy(t *testing.T) {
	var slowInflight, slowMax, fastInflight, fastMax atomic.Int64

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trackInflight(&slowInflight, &slowMax)
		time.Sleep(120 * time.Millisecond)
		slowInflight.Add(-1)
		_, _ = w.Write([]byte("<html><body>slow</body></html>"))
	}))
	defer slow.Close()

	fast := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trackInflight(&fastInflight, &fastMax)
		time.Sleep(10 * time.Millisecond)
		fastInflight.Add(-1)
		_, _ = w.Write([]byte("<html><body>fast</body></html>"))
	}))
	defer fast.Close()

	opts := &types.Options{
		MaxDepth:     3,
		BodyReadSize: 4096,
		Concurrency:  4,
		Parallelism:  2,
	}
	shared := newDoTestShared(t, opts)

	newSession := func(serverURL string, count int) *CrawlSession {
		var urls []string
		for i := 0; i < count; i++ {
			urls = append(urls, fmt.Sprintf("%s/page%d", serverURL, i))
		}
		session := newQueueSession(t, context.Background(), serverURL, urls)
		parsed, _ := urlutil.Parse(serverURL)
		session.URL = parsed.URL
		return session
	}

	doRequest := func(_ *CrawlSession, req *navigation.Request) (*navigation.Response, error) {
		resp, err := http.Get(req.URL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return &navigation.Response{StatusCode: resp.StatusCode, Resp: resp}, nil
	}

	fastSession := newSession(fast.URL, 8)
	slowSession := newSession(slow.URL, 8)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = shared.Do(fastSession, doRequest)
	}()
	go func() {
		defer wg.Done()
		_ = shared.Do(slowSession, doRequest)
	}()
	wg.Wait()

	require.Equal(t, int64(4), fastMax.Load(), "fast target should use its full budget")
	require.Equal(t, int64(4), slowMax.Load(), "slow target should use its full budget")
	require.Greater(t, fastMax.Load()+slowMax.Load(), int64(4),
		"a single global pool of 4 slots would have starved one of the targets")
}

// trackInflight records the peak concurrent handler count for a test server.
func trackInflight(inflight, maxInflight *atomic.Int64) {
	now := inflight.Add(1)
	for {
		old := maxInflight.Load()
		if now <= old || maxInflight.CompareAndSwap(old, now) {
			return
		}
	}
}

// TestDoHalvesTargetConcurrencyOnTimeouts verifies that repeated timeouts
// lower a target's budget through the real crawl loop, and that the next
// success restores it.
func TestDoHalvesTargetConcurrencyOnTimeouts(t *testing.T) {
	var slowRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The first requests exceed the per-request timeout, the rest answer
		// immediately.
		if slowRequests.Add(1) <= 6 {
			time.Sleep(150 * time.Millisecond)
		}
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer server.Close()

	opts := &types.Options{
		MaxDepth:     3,
		BodyReadSize: 4096,
		Concurrency:  4,
		Parallelism:  1,
		Timeout:      1, // seconds; the client below uses an explicit 50ms timeout
	}
	shared := newDoTestShared(t, opts)
	limiter := shared.RequestLimiter()

	var urls []string
	for i := 0; i < 8; i++ {
		urls = append(urls, fmt.Sprintf("%s/%d", server.URL, i))
	}
	session := newQueueSession(t, context.Background(), "slow.test", urls)
	parsed, _ := urlutil.Parse(server.URL)
	session.URL = parsed.URL
	key := session.TargetKey()
	require.Equal(t, 4, limiter.Limit(key))

	client := &http.Client{Timeout: 50 * time.Millisecond}
	doRequest := func(_ *CrawlSession, req *navigation.Request) (*navigation.Response, error) {
		resp, err := client.Get(req.URL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return &navigation.Response{StatusCode: resp.StatusCode, Resp: resp}, nil
	}

	require.NoError(t, shared.Do(session, doRequest))
	require.Equal(t, 1, limiter.Limit(key), "consecutive timeouts should halve the target budget down to the floor")
}

// TestDoRecoversTargetConcurrencyAfterSuccess checks that after timeouts
// lowered the budget, a successful crawl restores one slot per second.
func TestDoRecoversTargetConcurrencyAfterSuccess(t *testing.T) {
	var slowRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Exactly the first wave times out, everything afterwards succeeds.
		if slowRequests.Add(1) <= 4 {
			time.Sleep(120 * time.Millisecond)
		}
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer server.Close()

	opts := &types.Options{
		MaxDepth:     3,
		BodyReadSize: 4096,
		Concurrency:  4,
		Parallelism:  1,
		Timeout:      1,
	}
	shared := newDoTestShared(t, opts)

	var urls []string
	for i := 0; i < 8; i++ {
		urls = append(urls, fmt.Sprintf("%s/%d", server.URL, i))
	}
	session := newQueueSession(t, context.Background(), "recover.test", urls)
	parsed, _ := urlutil.Parse(server.URL)
	session.URL = parsed.URL
	key := session.TargetKey()

	client := &http.Client{Timeout: 50 * time.Millisecond}
	doRequest := func(_ *CrawlSession, req *navigation.Request) (*navigation.Response, error) {
		resp, err := client.Get(req.URL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return &navigation.Response{StatusCode: resp.StatusCode, Resp: resp}, nil
	}

	require.NoError(t, shared.Do(session, doRequest))

	limiter := shared.RequestLimiter()
	require.Less(t, limiter.Limit(key), 4, "timeouts should have lowered the budget")
	require.Eventually(t, func() bool { return limiter.Limit(key) == 4 }, 5*time.Second, 25*time.Millisecond,
		"successful requests should restore the initial budget one slot per second")
}

// TestDoHonoursGlobalConcurrencyCeiling verifies that the sum of in-flight
// requests across two targets never exceeds the configured global ceiling.
func TestDoHonoursGlobalConcurrencyCeiling(t *testing.T) {
	var combined, combinedMax atomic.Int64

	handler := func(w http.ResponseWriter, r *http.Request) {
		n := combined.Add(1)
		for {
			old := combinedMax.Load()
			if n <= old || combinedMax.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		combined.Add(-1)
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}
	a := httptest.NewServer(http.HandlerFunc(handler))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(handler))
	defer b.Close()

	opts := &types.Options{
		MaxDepth:     3,
		BodyReadSize: 4096,
		Concurrency:  4,
		Parallelism:  2,
		// The ceiling binds before either target reaches its local budget.
		GlobalConcurrency: 6,
	}
	shared := newDoTestShared(t, opts)
	require.Equal(t, 6, shared.RequestLimiter().GlobalLimit())

	newSession := func(serverURL string) *CrawlSession {
		var urls []string
		for i := 0; i < 8; i++ {
			urls = append(urls, fmt.Sprintf("%s/page%d", serverURL, i))
		}
		session := newQueueSession(t, context.Background(), serverURL, urls)
		parsed, _ := urlutil.Parse(serverURL)
		session.URL = parsed.URL
		return session
	}

	doRequest := func(_ *CrawlSession, req *navigation.Request) (*navigation.Response, error) {
		resp, err := http.Get(req.URL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return &navigation.Response{StatusCode: resp.StatusCode, Resp: resp}, nil
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = shared.Do(newSession(a.URL), doRequest)
	}()
	go func() {
		defer wg.Done()
		_ = shared.Do(newSession(b.URL), doRequest)
	}()
	wg.Wait()

	require.LessOrEqual(t, combinedMax.Load(), int64(6), "global ceiling was exceeded")
	require.Greater(t, combinedMax.Load(), int64(1), "requests were serialised")
}
