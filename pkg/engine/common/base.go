package common

import (
	"bytes"
	"context"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/PuerkitoBio/goquery"
	"github.com/go-rod/rod"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/engine/parser/files"
	"github.com/projectdiscovery/katana/pkg/navigation"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/projectdiscovery/katana/pkg/utils"
	"github.com/projectdiscovery/katana/pkg/utils/queue"
	"github.com/projectdiscovery/katana/pkg/utils/scope"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/errkit"
	httputil "github.com/projectdiscovery/utils/http"
	mapsutil "github.com/projectdiscovery/utils/maps"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/remeh/sizedwaitgroup"
)

// Shared represents the shared state and configuration used across all crawl sessions.
// It maintains common resources like HTTP headers, cookie jars, known files database,
// and crawler options that are reused for efficiency across multiple crawl operations.
const (
	backoffBase = 1 * time.Second
	backoffMax  = 30 * time.Second
)

type hostBackoff struct {
	consecutive atomic.Int32
}

const hostBackoffsCacheSize = 10000

type Shared struct {
	Headers           map[string]string
	KnownFiles        *files.KnownFiles
	Options           *types.CrawlerOptions
	Jar               *httputil.CookieJar
	PathTrie          *utils.PathTrie
	DomainPageCounter sync.Map
	ScopeStats        *ScopeStats
	hostBackoffs      *lru.Cache[string, *hostBackoff]

	// Scope-stats ticker lifecycle, guarded by statsStopMu in stats.go.
	statsActive  bool
	statsWaiters int
	statsStop    func()
}

// NewShared creates a new Shared instance with the provided crawler options.
// It initializes the HTTP headers, known files database (if configured), and an empty cookie jar.
// Returns an error if the HTTP client or cookie jar creation fails.
func NewShared(options *types.CrawlerOptions) (*Shared, error) {
	backoffCache, err := lru.New[string, *hostBackoff](hostBackoffsCacheSize)
	if err != nil {
		return nil, errkit.Wrap(err, "could not create backoff cache")
	}
	shared := &Shared{
		Headers:      options.Options.ParseCustomHeaders(),
		Options:      options,
		hostBackoffs: backoffCache,
		ScopeStats:   NewScopeStats(),
	}
	if options.Options.KnownFiles != "" {
		httpclient, _, err := BuildHttpClient(options.Dialer, options.Options, nil)
		if err != nil {
			return nil, errkit.Wrap(err, "could not create http client")
		}
		shared.KnownFiles = files.New(httpclient, options.Options.KnownFiles)
	}

	// create an empty cookie jar, this is used to store cookies during the crawl
	jar, err := httputil.NewCookieJar()
	if err != nil {
		return nil, errkit.Wrap(err, "could not create cookie jar")
	}
	shared.Jar = jar

	if options.Options.FilterSimilar {
		shared.PathTrie = utils.NewPathTrie(options.Options.FilterSimilarThreshold)
	}

	return shared, nil
}

// Enqueue adds one or more navigation requests to the crawl queue after applying
// validation checks. The method performs the following checks in order:
//  1. URL format validation
//  2. Query parameter handling (if IgnoreQueryParams is enabled)
//  3. Depth filtering - skips URLs exceeding MaxDepth before uniqueness check
//     to prevent caching URLs that would be rejected, allowing them to be
//     processed if discovered later at valid depths via different paths
//  4. Uniqueness filtering - prevents duplicate URL crawling
//  5. Cycle detection - identifies URLs stuck in redirect loops
//  6. Scope validation - ensures URLs belong to the allowed crawl scope
//
// For in-scope URLs, the method also handles path climbing when enabled,
// extracting and enqueuing parent directory paths.
// Out-of-scope URLs are sent to output if DisplayOutScope is enabled.
func (s *Shared) Enqueue(queue *queue.Queue, navigationRequests ...*navigation.Request) {
	for _, nr := range navigationRequests {
		if nr.URL == "" || !utils.IsURL(nr.URL) {
			if s.Options.Options.OnSkipURL != nil {
				s.Options.Options.OnSkipURL(nr.URL)
			}
			continue
		}

		reqUrl := nr.RequestURL()
		if s.Options.Options.IgnoreQueryParams {
			reqUrl = utils.ReplaceAllQueryParam(reqUrl, "")
		}
		if s.Options.Options.FilterSimilar {
			reqUrl = utils.FingerprintURL(reqUrl, s.PathTrie)
		}

		if (s.Options.Options.AuthCredentials != "" || s.Options.Options.RecordedFlow != "") && isLogoutURL(nr.URL) {
			continue
		}

		// When maximum depth is exceeded, output discovered URLs without enqueuing
		// them for visiting. Uniqueness is intentionally not consumed here so that
		// URLs can still be visited if later discovered at a valid depth via another path.
		if nr.Depth > s.Options.Options.MaxDepth {
			s.ScopeStats.RecordBlocked(nr.RootHostname, scope.ReasonDepthExceeded)
			s.OutputWithReason(nr, nil, ErrMaxDepthReached, scope.ReasonDepthExceeded)
			continue
		}

		if s.Options.Options.MaxDomainPages > 0 {
			if domain := nr.RootHostname; domain != "" {
				counter := s.DomainCounter(domain)
				if counter.Load() >= int64(s.Options.Options.MaxDomainPages) {
					continue
				}
			}
		}

		// Ignore blank URL items and only work on unique items
		if !s.Options.UniqueFilter.UniqueURL(reqUrl) && len(nr.CustomFields) == 0 {
			continue
		}
		// - URLs stuck in a loop
		if s.Options.UniqueFilter.IsCycle(nr.RequestURL()) {
			continue
		}

		// skip crawling if the endpoint is not in scope
		inScope, reason := s.ValidateScope(nr.URL, nr.RootHostname)
		if !inScope {
			s.ScopeStats.RecordBlocked(s.scopeTarget(nr), reason)
			// if the user requested anyway out of scope items
			// they are sent to output without visiting
			if s.Options.Options.DisplayOutScope {
				s.OutputWithReason(nr, nil, ErrOutOfScope, reason)
			}
			continue
		}

		s.ScopeStats.RecordAllowed(s.scopeTarget(nr))
		queue.Push(nr, s.priority(nr))

		if s.Options.Options.PathClimb {
			extractedParentURLs := utils.ExtractParentPaths(nr.URL)
			for _, extractedParentURL := range extractedParentURLs {
				if !utils.IsURL(extractedParentURL) {
					continue
				}

				checkURL := extractedParentURL
				if s.Options.Options.FilterSimilar {
					checkURL = utils.FingerprintURL(checkURL, s.PathTrie)
				}
				if !s.Options.UniqueFilter.UniqueURL(checkURL) {
					continue
				}
				if inScope, _ := s.ValidateScope(extractedParentURL, nr.RootHostname); !inScope {
					continue
				}

				parentDepth := nr.Depth
				if parentDepth > 0 {
					parentDepth--
				}

				parentReq := &navigation.Request{
					Method:       nr.Method,
					URL:          extractedParentURL,
					Depth:        parentDepth,
					RootHostname: nr.RootHostname,
					Source:       nr.Source,
					Tag:          "path-climb",
				}
				queue.Push(parentReq, s.priority(parentReq))
			}
		}
	}
}

// ValidateScope checks whether a given URL is within the allowed crawling scope
// based on the configured scope rules and the root hostname. It returns true
// (with scope.ReasonAllowed) when the URL passes scope validation, otherwise
// false with the scope.Reason code explaining the rejection.
func (s *Shared) ValidateScope(URL string, root string) (bool, scope.Reason) {
	parsed, err := urlutil.Parse(URL)
	if err != nil {
		gologger.Warning().Msgf("failed to parse url while validating scope: %v", err)
		return false, scope.ReasonOutOfBound
	}
	scopeValidated, reason, err := s.Options.ScopeManager.ValidateWithReason(parsed.URL, root)
	if err != nil {
		gologger.Warning().Msgf("failed to validate scope for %q: %v", URL, err)
		return false, scope.ReasonOutOfBound
	}
	return scopeValidated, reason
}

// scopeTarget returns the root hostname a navigation request belongs to. Some
// early requests (e.g. the seed itself) do not carry RootHostname, so the URL
// host is used as a fallback to keep statistics attributed to a real target.
func (s *Shared) scopeTarget(nr *navigation.Request) string {
	if nr.RootHostname != "" {
		return nr.RootHostname
	}
	if parsed, err := urlutil.Parse(nr.URL); err == nil {
		return parsed.Hostname()
	}
	return ""
}

// Output writes a crawl result to the configured output writer.
// It creates a Result object containing the navigation request, response (if any),
// and error information (if any), then writes it to the output writer.
// If an OnResult callback is configured and output writing succeeds, the callback is invoked.
func (s *Shared) Output(navigationRequest *navigation.Request, navigationResponse *navigation.Response, err error) {
	s.OutputWithReason(navigationRequest, navigationResponse, err, scope.ReasonAllowed)
}

// OutputWithReason is Output with an explicit scope.Reason code. The reason is
// carried on the written Result so consumers can tell which rule intercepted
// the request; it is empty for normally visited URLs.
func (s *Shared) OutputWithReason(navigationRequest *navigation.Request, navigationResponse *navigation.Response, err error, reason scope.Reason) {
	var errData string
	if err != nil {
		errData = err.Error()
	}
	// Write the found result to output
	result := &output.Result{
		Timestamp:  time.Now(),
		Request:    navigationRequest,
		Response:   navigationResponse,
		Error:      errData,
		SkipReason: string(reason),
	}

	outputErr := s.Options.OutputWriter.Write(result)

	if s.Options.Options.OnResult != nil && outputErr == nil {
		s.Options.Options.OnResult(*result)
	}
}

var logoutURLPattern = regexp.MustCompile(`(?i)(log[\s_-]?out|sign[\s_-]?out|signout|deconnexion|cerrar[\s_-]?sesion|sair|abmelden|uitloggen|ausloggen|disconnect|terminate|end[\s_-]?session|salir|desconectar|afmelden|wyloguj|sign[\s_-]?off)`)

func isLogoutURL(rawURL string) bool {
	return logoutURLPattern.MatchString(rawURL)
}

func (s *Shared) DomainCounter(domain string) *atomic.Int64 {
	val, _ := s.DomainPageCounter.LoadOrStore(domain, &atomic.Int64{})
	return val.(*atomic.Int64)
}

func (s *Shared) backoffFor(host string) *hostBackoff {
	if val, ok := s.hostBackoffs.Get(host); ok {
		return val
	}
	b := &hostBackoff{}
	s.hostBackoffs.Add(host, b)
	return b
}

// ApplyBackoff sleeps if the host has accumulated throttle signals.
func (s *Shared) ApplyBackoff(host string) {
	b := s.backoffFor(host)
	n := b.consecutive.Load()
	if n <= 0 {
		return
	}
	delay := time.Duration(math.Min(
		float64(backoffBase)*math.Pow(2, float64(n-1)),
		float64(backoffMax),
	))
	jitter := time.Duration(rand.Int64N(int64(delay) / 2))
	time.Sleep(delay + jitter)
}

// RecordThrottle increments backoff state for a throttled host.
func (s *Shared) RecordThrottle(host string, statusCode int) {
	b := s.backoffFor(host)
	b.consecutive.Add(1)
	gologger.Debug().Msgf("Host %s returned %d, backing off", host, statusCode)
}

// RecordSuccess decrements backoff state on a successful response.
func (s *Shared) RecordSuccess(host string) {
	b := s.backoffFor(host)
	if b.consecutive.Load() > 0 {
		b.consecutive.Add(-1)
	}
}

// IsThrottled returns true if the status code indicates rate limiting.
func IsThrottled(statusCode int) bool {
	return statusCode == http.StatusTooManyRequests || statusCode == http.StatusServiceUnavailable
}

// CrawlSession represents an active crawling session for a specific target URL.
// It maintains the session context, cancellation function, parsed URL information,
// the request queue, and HTTP/browser clients needed for the crawl operation.
type CrawlSession struct {
	Ctx        context.Context
	CancelFunc context.CancelFunc
	URL        *url.URL
	Hostname   string
	Queue      *queue.Queue
	HttpClient *retryablehttp.Client
	Browser    *rod.Browser
}

// NewCrawlSessionWithURL creates and initializes a new crawl session for the specified URL.
// It performs the following initialization steps:
//  1. Creates a context with optional timeout based on CrawlDuration setting
//  2. Parses the target URL and extracts the hostname
//  3. Initializes the request queue with the configured strategy
//  4. Enqueues the initial URL and any known files for the target
//  5. Sets up the HTTP client with response parsing callbacks
//
// Returns the initialized CrawlSession or an error if initialization fails.
func (s *Shared) NewCrawlSessionWithURL(URL string) (*CrawlSession, error) {
	parentCtx := s.Options.Options.Context
	if parentCtx == nil {
		parentCtx = context.Background()
	}
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)
	if s.Options.Options.CrawlDuration.Seconds() > 0 {
		ctx, cancel = context.WithTimeout(parentCtx, s.Options.Options.CrawlDuration)
	} else {
		ctx, cancel = context.WithCancel(parentCtx)
	}

	parsed, err := urlutil.Parse(URL)
	if err != nil {
		cancel()
		return nil, errkit.Wrap(err, "could not parse root URL")
	}
	hostname := parsed.Hostname()

	queue, err := queue.New(s.Options.Options.Strategy)
	if err != nil {
		cancel()
		return nil, err
	}
	queue.Push(&navigation.Request{Method: http.MethodGet, URL: URL, Depth: 0, SkipValidation: true}, 0)

	if s.KnownFiles != nil {
		navigationRequests, err := s.KnownFiles.RequestWithContext(ctx, URL)
		if err != nil {
			gologger.Warning().Msgf("Could not parse known files for %s: %s\n", URL, err)
		}
		s.Enqueue(queue, navigationRequests...)
	}
	var scopeValidator ScopeValidator
	if s.Options.ScopeManager != nil {
		scopeValidator = func(u *url.URL) bool {
			validated, err := s.Options.ScopeManager.Validate(u, hostname)
			if err != nil {
				return false
			}
			return validated
		}
	}
	httpclient, _, err := BuildHttpClient(s.Options.Dialer, s.Options.Options, func(resp *http.Response, depth int) {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, int64(s.Options.Options.BodyReadSize)))
		reader, _ := goquery.NewDocumentFromReader(bytes.NewReader(body))
		var technologyKeys []string
		if s.Options.Wappalyzer != nil {
			technologies := s.Options.Wappalyzer.Fingerprint(resp.Header, body)
			technologyKeys = mapsutil.GetKeys(technologies)
		}
		navigationResponse := &navigation.Response{
			Depth:         depth + 1,
			RootHostname:  hostname,
			Resp:          resp,
			Body:          string(body),
			Reader:        reader,
			Technologies:  technologyKeys,
			StatusCode:    resp.StatusCode,
			Headers:       utils.FlattenHeaders(resp.Header),
			KnowledgeBase: s.Options.BuildKnowledgeBase(string(body), resp.Request, resp),
		}
		navigationRequests := s.Options.Parser.ParseResponse(navigationResponse)
		s.Enqueue(queue, navigationRequests...)
	}, scopeValidator)
	if err != nil {
		cancel()
		return nil, errkit.Wrap(err, "could not create http client")
	}
	crawlSession := &CrawlSession{
		Ctx:        ctx,
		CancelFunc: cancel,
		URL:        parsed.URL,
		Hostname:   hostname,
		Queue:      queue,
		HttpClient: httpclient,
	}
	return crawlSession, nil
}

// DoRequestFunc is a function type for executing navigation requests.
// Implementations should perform the actual HTTP request or browser navigation
// and return the response or an error. This allows different crawling strategies
// (standard HTTP vs. headless browser) to provide their own request logic.
type DoRequestFunc func(crawlSession *CrawlSession, req *navigation.Request) (*navigation.Response, error)

// AcceptRequest returns the request in a popped queue item when it is a URL
// that passes the path and scope filters. When ok is false the request is
// skipped and reason carries the scope.Reason code of the rule that rejected
// it (scope_path_filtered or scope_out_of_bound); reason is empty for items
// that are skipped before any scope decision (wrong queue item type, malformed
// URL). Every rejection is recorded on the per-target ScopeStats collector.
func (s *Shared) AcceptRequest(crawlSession *CrawlSession, item interface{}) (req *navigation.Request, inScope bool, reason scope.Reason, ok bool) {
	req, ok = item.(*navigation.Request)
	if !ok {
		return nil, false, scope.ReasonAllowed, false
	}

	if !utils.IsURL(req.URL) {
		if s.Options.Options.OnSkipURL != nil {
			s.Options.Options.OnSkipURL(req.URL)
		}
		gologger.Debug().Msgf("`%v` not a url. skipping", req.URL)
		return nil, false, scope.ReasonAllowed, false
	}

	if !s.Options.ValidatePath(req.URL) {
		gologger.Debug().Msgf("`%v` filtered path. skipping", req.URL)
		s.ScopeStats.RecordBlocked(crawlSession.Hostname, scope.ReasonPathFiltered)
		return nil, false, scope.ReasonPathFiltered, false
	}

	inScope, reason, scopeErr := s.Options.ValidateScopeWithReason(req.URL, crawlSession.Hostname)
	if scopeErr != nil {
		gologger.Debug().Msgf("Error validating scope for `%v`: %v. skipping", req.URL, scopeErr)
		s.ScopeStats.RecordBlocked(crawlSession.Hostname, scope.ReasonOutOfBound)
		return nil, false, scope.ReasonOutOfBound, false
	}
	if !req.SkipValidation && !inScope {
		gologger.Debug().Msgf("`%v` not in scope. skipping", req.URL)
		s.ScopeStats.RecordBlocked(crawlSession.Hostname, reason)
		return nil, false, reason, false
	}
	return req, inScope, scope.ReasonAllowed, true
}

// Do executes the main crawling loop for the given crawl session.
// It processes items from the queue concurrently (respecting the Concurrency limit),
// validates each request (URL format, path filters, scope), applies rate limiting
// and delays, executes the request using the provided doRequest function, writes
// results to output, and enqueues any newly discovered URLs from responses.
//
// The method returns when the queue is empty or the session context is cancelled
// (due to timeout or manual cancellation). Returns an error if the context is cancelled.
func (s *Shared) Do(crawlSession *CrawlSession, doRequest DoRequestFunc) error {
	wg := sizedwaitgroup.New(s.Options.Options.Concurrency)
	for item := range crawlSession.Queue.PopWithContext(crawlSession.Ctx) {
		if crawlSession.Ctx.Err() != nil {
			break
		}

		req, inScope, _, ok := s.AcceptRequest(crawlSession, item)
		if !ok {
			crawlSession.Queue.Done()
			continue
		}

		wg.Add()
		go func() {
			defer wg.Done()
			defer crawlSession.Queue.Done()

			// Race Take() against the session context so that workers
			// don't block shutdown waiting for the next limiter tick
			// (the limiter is bound to options.Context, not the session).
			//
			// Note: when the session is cancelled mid-Take, this inner
			// goroutine outlives the worker and stays blocked on the
			// limiter until the next tick or until RateLimit.Stop() is
			// called by CrawlerOptions.Close(). The leak is therefore
			// bounded by Close() and acceptable.
			takeDone := make(chan struct{})
			go func() {
				if s.Options.HostRateLimit != nil {
					_ = s.Options.HostRateLimit.Take(crawlSession.Hostname)
				} else if s.Options.RateLimit != nil {
					s.Options.RateLimit.Take()
				}
				close(takeDone)
			}()
			select {
			case <-crawlSession.Ctx.Done():
				return
			case <-takeDone:
			}
			s.ApplyBackoff(crawlSession.Hostname)

			if crawlSession.Ctx.Err() != nil {
				return
			}

			// Context-aware delay
			if s.Options.Options.Delay > 0 {
				select {
				case <-crawlSession.Ctx.Done():
					return
				case <-time.After(time.Duration(s.Options.Options.Delay) * time.Second):
				}
			}

			if s.Options.Options.MaxDomainPages > 0 {
				counter := s.DomainCounter(crawlSession.Hostname)
				if counter.Add(1) > int64(s.Options.Options.MaxDomainPages) {
					return
				}
			}

			resp, err := doRequest(crawlSession, req)

			if resp != nil && IsThrottled(resp.StatusCode) {
				s.RecordThrottle(crawlSession.Hostname, resp.StatusCode)
			} else if resp != nil {
				s.RecordSuccess(crawlSession.Hostname)
			}

			if inScope {
				s.Output(req, resp, err)
			}

			if err != nil {
				gologger.Warning().Msgf("Could not request seed URL %s: %s\n", req.URL, err)
				outputError := &output.Error{
					Timestamp: time.Now(),
					Endpoint:  req.RequestURL(),
					Source:    req.Source,
					Error:     err.Error(),
				}
				_ = s.Options.OutputWriter.WriteErr(outputError)
				return
			}
			if resp == nil || resp.Resp == nil || resp.Reader == nil {
				return
			}
			if s.Options.Options.DisableRedirects && resp.IsRedirect() {
				return
			}

			navigationRequests := s.Options.Parser.ParseResponse(resp)
			s.Enqueue(crawlSession.Queue, navigationRequests...)
		}()
	}
	wg.Wait()
	return crawlSession.Ctx.Err()
}
