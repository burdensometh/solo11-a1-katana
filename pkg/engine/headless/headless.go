package headless

import (
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lmittmann/tint"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/engine/common"
	"github.com/projectdiscovery/katana/pkg/engine/headless/auth"
	"github.com/projectdiscovery/katana/pkg/engine/headless/browser"
	"github.com/projectdiscovery/katana/pkg/engine/headless/captcha"
	_ "github.com/projectdiscovery/katana/pkg/engine/headless/captcha/capsolver"
	"github.com/projectdiscovery/katana/pkg/engine/headless/crawler"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/projectdiscovery/katana/pkg/utils"
	"github.com/projectdiscovery/katana/pkg/utils/scope"
)

type Headless struct {
	logger  *slog.Logger
	options *types.CrawlerOptions

	pathTrie *utils.PathTrie

	// ScopeStats collects per-target allowed/blocked counters for headless
	// crawls; the headless crawler architecture does not go through
	// common.Shared, so the collector is driven via the scope validator
	// wrapper and the depth check in headless.Crawl.
	scopeStats *common.ScopeStats

	debugger *CrawlDebugger

	hooks Hooks

	mu             sync.Mutex
	activeCrawlers map[*crawler.Crawler]struct{}
}

// New returns a new headless crawler instance
func New(options *types.CrawlerOptions) (*Headless, error) {
	logger := newLogger(options)

	headless := &Headless{
		logger:         logger,
		options:        options,
		scopeStats:     common.NewScopeStats(),
		activeCrawlers: make(map[*crawler.Crawler]struct{}),
	}
	if options.Options.FilterSimilar {
		headless.pathTrie = utils.NewPathTrie(options.Options.FilterSimilarThreshold)
	}

	// Show crawl debugger if verbose is enabled
	if options.Options.Verbose {
		headless.debugger = NewCrawlDebugger(8089)
	}

	return headless, nil
}

// writeResult mirrors common.Shared.Output so library users get OnResult
// from headless crawls as they do from standard and hybrid.
func (h *Headless) writeResult(result *output.Result) error {
	if err := h.options.OutputWriter.Write(result); err != nil {
		return err
	}
	if h.options.Options.OnResult != nil {
		h.options.Options.OnResult(*result)
	}
	return nil
}

func newLogger(options *types.CrawlerOptions) *slog.Logger {
	if options.Logger != nil {
		return options.Logger
	}

	writer := os.Stderr

	// set global logger with custom options
	level := slog.LevelInfo
	if options.Options.Debug {
		level = slog.LevelDebug
	}
	logger := slog.New(
		tint.NewHandler(writer, &tint.Options{
			Level:      level,
			TimeFormat: time.Kitchen,
		}),
	)
	return logger
}

// rootHostnameOf extracts the hostname from an absolute URL, falling back to
// the raw input when it cannot be parsed.
func rootHostnameOf(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return parsed.Hostname()
}

// validateScopeFunc returns the browser scope validator used by the headless
// crawler. Every decision is recorded on the per-target ScopeStats collector:
// rejected URLs are counted under scope_out_of_bound, accepted URLs are
// counted as allowed. The browser invokes the validator at several decision
// points for the same URL, so decisions are de-duplicated per URL within one
// target to keep counters meaningful.
func (h *Headless) validateScopeFunc(URL string) browser.ScopeValidator {
	parsedURL, err := url.Parse(URL)
	if err != nil {
		return func(string) bool { return true }
	}
	rootHostname := parsedURL.Hostname()

	// seen records the first decision (allowed=true/false) observed for each
	// URL within this target crawl so repeated validator calls do not inflate
	// the counters.
	var seen sync.Map // map[string]bool

	record := func(rawURL string, allowed bool, reason scope.Reason) {
		if _, loaded := seen.LoadOrStore(rawURL, allowed); loaded {
			return
		}
		if allowed {
			h.scopeStats.RecordAllowed(rootHostname)
		} else {
			h.scopeStats.RecordBlocked(rootHostname, reason)
		}
	}

	return func(s string) bool {
		if h.options.ScopeManager == nil {
			record(s, true, scope.ReasonAllowed)
			return true
		}
		parsed, err := url.Parse(s)
		if err != nil {
			record(s, false, scope.ReasonOutOfBound)
			return false
		}
		validated, reason, err := h.options.ScopeManager.ValidateWithReason(parsed, rootHostname)
		if err != nil || !validated {
			if err != nil {
				reason = scope.ReasonOutOfBound
			}
			record(s, false, reason)
			return false
		}
		record(s, true, scope.ReasonAllowed)
		return true
	}
}

// Crawl executes the headless crawling on a given URL
func (h *Headless) Crawl(URL string) error {
	if h.debugger != nil {
		h.debugger.StartURL(URL, 0)
	}
	defer func() {
		if h.debugger != nil {
			h.debugger.EndURL(URL)
		}
	}()

	scopeValidator := h.validateScopeFunc(URL)
	// The headless crawler handles depth and scope internally. Periodic scope
	// summaries follow the same -stats switch as the progress stats; counters
	// are always collected via the validator wrapper above.
	if h.options.Options.ShowStatistics {
		statsInterval := time.Duration(h.options.Options.StatsInterval) * time.Second
		stopScopeStats := h.scopeStats.StartPeriodicReport(statsInterval)
		defer stopScopeStats()
	}
	targetHostname := rootHostnameOf(URL)
	crawlOpts := crawler.Options{
		Context:               h.options.Options.Context,
		UseInstalledChrome:    h.options.Options.UseInstalledChrome,
		ChromiumPath:          h.options.Options.SystemChromePath,
		MaxDepth:              h.options.Options.MaxDepth,
		ShowBrowser:           h.options.Options.ShowBrowser,
		MaxCrawlDuration:      h.options.Options.CrawlDuration,
		MaxFailureCount:       h.options.Options.MaxFailureCount,
		NoSandbox:             h.options.Options.HeadlessNoSandbox,
		NoIncognito:           h.options.Options.HeadlessNoIncognito,
		UserDataDir:           h.options.Options.ChromeDataDir,
		Proxy:                 h.options.Options.Proxy,
		MaxBrowsers:           1,
		PageMaxTimeout:        30 * time.Second,
		ScopeValidator:        scopeValidator,
		AutomaticFormFill:     h.options.Options.AutomaticFormFill,
		CustomHeaders:         h.options.Options.ParseCustomHeaders(),
		RootURL:               URL,
		Interactive:           h.options.Options.Interactive,
		InteractionDepth:      h.options.Options.InteractionDepth,
		InteractionSelector:   h.options.Options.InteractionSelector,
		InteractionExclude:    h.options.Options.InteractionExclude,
		InteractionMaxStates:  h.options.Options.InteractionMaxStates,
		InteractionMaxActions: h.options.Options.InteractionMaxActions,
		InteractionSettle:     h.options.Options.InteractionSettle,
		InteractionDuration:   h.options.Options.InteractionDuration,
		PageLoadStrategy:      h.options.Options.PageLoadStrategy,
		ChromeWSUrl:           h.options.Options.ChromeWSUrl,
		DOMWaitTime:           h.options.Options.DOMWaitTime,
		MaxScrollSteps:        h.options.Options.MaxScrollSteps,
		OnDepthExceeded: func(int) {
			h.scopeStats.RecordBlocked(targetHostname, scope.ReasonDepthExceeded)
		},
		RequestCallback: func(rr *output.Result) {
			if rr == nil || rr.Request == nil {
				return
			}
			if scopeValidator != nil && !scopeValidator(rr.Request.URL) {
				return
			}

			// Register the real (intercepted) request URL before parsing the
			// response body for additional discoveries. This ensures that real
			// results with full response data always take priority over
			// synthetic Request-only entries produced by performAdditionalAnalysis.
			isUnique := h.isUniqueURL(rr.Request.URL)

			// Always run additional analysis regardless of uniqueness so we
			// don't miss URL discoveries embedded in a response body that the
			// browser happened to fetch more than once.
			navigationRequests := h.performAdditionalAnalysis(rr)
			for _, req := range navigationRequests {
				if err := h.writeResult(req); err != nil {
					h.logger.Debug("failed to write navigation result",
						slog.String("url", func() string {
							if req != nil && req.Request != nil {
								return req.Request.URL
							}
							return ""
						}()),
						slog.String("error", err.Error()),
					)
				}
			}

			if !isUnique {
				return
			}

			if rr.Response != nil {
				var req *http.Request
				if rr.Response.Resp != nil {
					req = rr.Response.Resp.Request
				}
				rr.Response.KnowledgeBase = h.options.BuildKnowledgeBase(rr.Response.Body, req, rr.Response.Resp)
				if h.options.Options.OmitRaw {
					rr.Response.Raw = ""
				}
				if h.options.Options.OmitBody {
					rr.Response.Body = ""
				}
			}
			if err := h.writeResult(rr); err != nil {
				h.logger.Debug("failed to write result",
					slog.String("error", err.Error()),
				)
			}
		},
		Logger:              h.logger,
		ChromeUser:          h.options.ChromeUser,
		EnableDiagnostics:   h.options.Options.EnableDiagnostics,
		Trace:               h.options.Options.EnableDiagnostics,
		CookieConsentBypass: true,
		UserArguments:       h.options.Options.ParseHeadlessOptionalArguments(),
		DitClassifier:       h.options.DitClassifier,
		FormDecider:         h.options.FormDecider(),
		Hooks:               h.hooks,
	}

	if creds := h.options.Options.AuthCredentials; creds != "" {
		parts := strings.SplitN(creds, ":", 2)
		crawlOpts.AuthUsername = parts[0]
		if len(parts) > 1 {
			crawlOpts.AuthPassword = parts[1]
		}
	}

	if path := h.options.Options.RecordedFlow; path != "" {
		steps, err := auth.StepsFromFile(path, crawlOpts.AuthUsername, crawlOpts.AuthPassword)
		if err != nil {
			return err
		}
		crawlOpts.AuthSteps = steps
	}

	if provider := h.options.Options.CaptchaSolverProvider; provider != "" {
		gologger.Debug().Msgf("captcha solver enabled: provider=%s", provider)
		handler, err := captcha.NewHandler(provider, h.options.Options.CaptchaSolverAPIKey)
		if err != nil {
			gologger.Warning().Msgf("captcha handler init failed: %s", err)
		} else {
			crawlOpts.CaptchaHandler = handler
		}
	}

	// TODO: Make the crawling multi-threaded. Right now concurrency is hardcoded to 1.

	if capturer, ok := h.options.OutputWriter.(interface{ Capture(*output.Result) }); ok {
		crawlOpts.TrafficCallback = capturer.Capture
	}

	headlessCrawler, err := crawler.New(crawlOpts)
	if err != nil {
		return err
	}
	h.mu.Lock()
	if h.activeCrawlers == nil {
		h.activeCrawlers = make(map[*crawler.Crawler]struct{})
	}
	h.activeCrawlers[headlessCrawler] = struct{}{}
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.activeCrawlers, headlessCrawler)
		h.mu.Unlock()
		headlessCrawler.Close()
	}()

	if err = headlessCrawler.Crawl(URL); err != nil {
		return err
	}
	return nil
}

func (h *Headless) Close() error {
	h.mu.Lock()
	crawlers := make([]*crawler.Crawler, 0, len(h.activeCrawlers))
	for c := range h.activeCrawlers {
		crawlers = append(crawlers, c)
	}
	h.mu.Unlock()

	for _, c := range crawlers {
		c.Close()
	}

	if h.debugger != nil {
		h.debugger.Close()
	}
	return nil
}

func (h *Headless) isUniqueURL(rawURL string) bool {
	dedupKey := rawURL
	if h.options.Options.IgnoreQueryParams {
		dedupKey = utils.ReplaceAllQueryParam(dedupKey, "")
	}
	if h.options.Options.FilterSimilar {
		dedupKey = utils.FingerprintURL(dedupKey, h.pathTrie)
	}
	return h.options.UniqueFilter.UniqueURL(dedupKey)
}

func (h *Headless) performAdditionalAnalysis(rr *output.Result) []*output.Result {
	newNavigations := h.options.Parser.ParseResponse(rr.Response)

	navigationRequests := make([]*output.Result, 0)
	for _, resp := range newNavigations {
		if !h.isUniqueURL(resp.URL) {
			continue
		}
		navigationRequests = append(navigationRequests, &output.Result{
			Request: resp,
		})
	}
	return navigationRequests
}
