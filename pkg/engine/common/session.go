package common

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/katana/pkg/navigation"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/errkit"
)

// DefaultMaxLoginFailures is how many consecutive re-login attempts may fail
// before the crawl is stopped instead of collecting more login pages.
const DefaultMaxLoginFailures = 3

// maxSessionRequeues bounds how many times a single request is re-queued
// after session refreshes. It keeps a request from bouncing forever when the
// server keeps answering with a login wall even though logins "succeed".
const maxSessionRequeues = 3

// maxLoginBodySize caps how much of a login page is parsed when looking for
// the credential form.
const maxLoginBodySize = 4 << 20

// ErrSessionCircuitOpen is returned (wrapped) when re-login keeps failing and
// the crawl is stopped: continuing would only harvest unauthenticated pages.
var ErrSessionCircuitOpen = errkit.New("session re-login circuit open")

// LoginFunc re-establishes the authenticated session, e.g. by submitting a
// login form. loginURL is the login page URL learned from the response that
// exposed the expired session. A successful call must leave the fresh session
// state (cookies) in the crawl's shared cookie jar.
type LoginFunc func(ctx context.Context, loginURL string) error

// loginURLPattern matches URL paths commonly used for login pages. It mirrors
// logoutURLPattern in base.go.
var loginURLPattern = regexp.MustCompile(`(?i)(log[\s_-]?in|sign[\s_-]?in|signin|connexion|anmelden|einloggen|inloggen|iniciar[\s_-]?sesion|accedi|entrar|session[/_-]?new)`)

// SessionGuard detects expired authenticated sessions mid-crawl and
// re-establishes them with single-flight semantics.
//
// When a response looks like a login page, the goroutine that noticed calls
// EnsureSession. Exactly one goroutine runs the login at a time; the others
// block on the mutex and, once it is released, reuse the session the winner
// established instead of logging in again. Consecutive login failures are
// counted globally and trip a circuit breaker at maxFailures, which cancels
// the crawl via the bound stop function.
type SessionGuard struct {
	loginFn     LoginFunc
	maxFailures int
	detectBody  bool

	mu         sync.Mutex // serializes login attempts
	generation atomic.Uint64
	failures   int // consecutive login failures, guarded by mu
	tripped    atomic.Bool
	tripErr    error // written before tripped is set, read after
	stopFn     func()

	loginURL atomic.Value // string, last login page URL learned from a response
}

// SessionGuardOption customizes a SessionGuard.
type SessionGuardOption func(*SessionGuard)

// WithMaxLoginFailures sets how many consecutive login failures trip the
// circuit breaker. Values <= 0 keep the default of DefaultMaxLoginFailures.
func WithMaxLoginFailures(n int) SessionGuardOption {
	return func(g *SessionGuard) {
		if n > 0 {
			g.maxFailures = n
		}
	}
}

// WithLoginBodyDetection toggles treating a credential form in a response
// body as an expired-session signal. It catches sites that serve the login
// page with a 200 rewrite instead of a redirect. Default is on.
func WithLoginBodyDetection(enabled bool) SessionGuardOption {
	return func(g *SessionGuard) {
		g.detectBody = enabled
	}
}

// NewSessionGuard creates a guard that re-establishes sessions with loginFn.
func NewSessionGuard(loginFn LoginFunc, opts ...SessionGuardOption) *SessionGuard {
	g := &SessionGuard{
		loginFn:     loginFn,
		maxFailures: DefaultMaxLoginFailures,
		detectBody:  true,
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// Generation returns the current session generation. It changes every time a
// login succeeds, so a caller can tell whether the session was refreshed
// since it captured the value.
func (g *SessionGuard) Generation() uint64 {
	return g.generation.Load()
}

// Tripped reports whether the circuit breaker stopped the crawl.
func (g *SessionGuard) Tripped() bool {
	return g.tripped.Load()
}

// TripError returns the error recorded when the circuit breaker tripped.
func (g *SessionGuard) TripError() error {
	if !g.tripped.Load() {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tripErr
}

// Failures returns the current consecutive login failure count.
func (g *SessionGuard) Failures() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.failures
}

// BindStop registers the function that cancels the active crawl session when
// the circuit breaker trips. Called once per crawl session.
func (g *SessionGuard) BindStop(stop func()) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stopFn = stop
}

// SetLoginURL seeds the login page URL, e.g. when it is known up front.
// Normally the guard learns it from the first response that exposes an
// expired session.
func (g *SessionGuard) SetLoginURL(rawURL string) {
	g.loginURL.Store(rawURL)
}

// LoginURL returns the last learned login page URL, or "" if none was seen.
func (g *SessionGuard) LoginURL() string {
	if v, ok := g.loginURL.Load().(string); ok {
		return v
	}
	return ""
}

// IsLoginResponse reports whether a response indicates the crawl session has
// expired: the request was redirected to a login page (or, with
// DisableRedirects, points there via its Location header), or the body is a
// credential form served under a non-login URL. A response for a URL that is
// itself a login page is never flagged - that page was asked for.
func (g *SessionGuard) IsLoginResponse(req *navigation.Request, resp *navigation.Response) bool {
	if req == nil || resp == nil || resp.Resp == nil || resp.Resp.Request == nil || resp.Resp.Request.URL == nil {
		return false
	}
	if isLoginURL(req.URL) {
		return false
	}
	finalURL := resp.Resp.Request.URL

	// Redirects disabled: the response itself is the redirect.
	if resp.IsRedirect() {
		if loc, err := resp.Resp.Location(); err == nil && loc != nil && loginURLPattern.MatchString(loc.Path) {
			g.learnLoginURL(loc.String())
			return true
		}
		return false
	}

	// Redirects followed: the final URL is a login page different from what
	// was requested (the requested path cannot be login-ish, see above).
	if loginURLPattern.MatchString(finalURL.Path) {
		g.learnLoginURL(finalURL.String())
		return true
	}

	// 200 rewrite: the body itself is a credential form.
	if g.detectBody && resp.Reader != nil {
		if _, ok := credentialForm(resp.Reader); ok {
			g.learnLoginURL(finalURL.String())
			return true
		}
	}
	return false
}

// EnsureSession makes sure the session was refreshed since generation seen,
// logging in if necessary. Callers capture Generation() before issuing their
// request and pass it here when the response showed an expired session:
//   - the generation already advanced: another goroutine refreshed the
//     session, return immediately and reuse it;
//   - otherwise take the lock and re-check. The loser of the lock race finds
//     an advanced generation and returns without logging in again.
//
// Returns ErrSessionCircuitOpen (wrapped) once maxFailures consecutive logins
// failed; the bound stop function is called to halt the crawl.
func (g *SessionGuard) EnsureSession(ctx context.Context, seen uint64) error {
	if g.tripped.Load() {
		return g.TripError()
	}
	if g.generation.Load() != seen {
		return nil
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	// A goroutine that waited on the lock reuses the winner's session.
	if g.generation.Load() != seen {
		return nil
	}
	if g.tripped.Load() {
		return g.tripErr
	}

	loginURL := g.LoginURL()
	if loginURL == "" {
		return errkit.New("session expired but no login page URL is known")
	}

	err := g.loginFn(ctx, loginURL)
	if err == nil {
		g.failures = 0
		g.generation.Add(1)
		return nil
	}
	if ctx.Err() != nil {
		// The crawl is shutting down; do not count shutdown-induced
		// failures against the circuit breaker.
		return ctx.Err()
	}
	g.failures++
	if g.failures >= g.maxFailures {
		g.tripErr = errkit.Wrapf(ErrSessionCircuitOpen, "re-login failed %d consecutive times, stopping crawl (last error: %s)", g.failures, err)
		g.tripped.Store(true)
		if g.stopFn != nil {
			g.stopFn()
		}
		return g.tripErr
	}
	return errkit.Wrapf(err, "re-login attempt %d/%d failed", g.failures, g.maxFailures)
}

func (g *SessionGuard) learnLoginURL(rawURL string) {
	if parsed, err := url.Parse(rawURL); err == nil {
		parsed.Fragment = ""
		rawURL = parsed.String()
	}
	g.loginURL.Store(rawURL)
}

func urlPath(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return parsed.Path
}

// isLoginURL reports whether a URL's path looks like a login page.
func isLoginURL(rawURL string) bool {
	return loginURLPattern.MatchString(urlPath(rawURL))
}

// credentialForm returns the first form that looks like a credential form: it
// contains a password input and posts to a login-ish or empty (self) action.
// Password forms with other actions (change-password, registration) are not
// treated as login walls.
func credentialForm(doc *goquery.Document) (*goquery.Selection, bool) {
	var found *goquery.Selection
	doc.Find("form").EachWithBreak(func(_ int, form *goquery.Selection) bool {
		if form.Find(`input[type="password"]`).Length() == 0 {
			return true
		}
		action := strings.TrimSpace(attrOr(form, "action", ""))
		if action != "" && !loginURLPattern.MatchString(action) {
			return true
		}
		found = form
		return false
	})
	return found, found != nil
}

func attrOr(sel *goquery.Selection, name, fallback string) string {
	if v, ok := sel.Attr(name); ok {
		return v
	}
	return fallback
}

// HTTPFormLogin performs classic HTML form authentication: GET the login
// page, submit its credential form with the configured username/password and
// verify the session stuck. The client must carry the crawl's shared cookie
// jar so the fresh session is visible to all crawl goroutines at once.
type HTTPFormLogin struct {
	Client   *retryablehttp.Client
	Username string
	Password string
}

// Login implements the form login. It fails when the login page has no
// credential form, when the submission is rejected (401/403), or when the
// post-submit redirect chain lands back on a login page.
func (l *HTTPFormLogin) Login(ctx context.Context, loginURL string) error {
	if l.Client == nil {
		return errkit.New("login: no http client configured")
	}

	loginPage, err := l.do(ctx, http.MethodGet, loginURL, "")
	if err != nil {
		return errkit.Wrap(err, "login: could not fetch login page")
	}
	body, err := io.ReadAll(io.LimitReader(loginPage.Body, maxLoginBodySize))
	_ = loginPage.Body.Close()
	if err != nil {
		return errkit.Wrap(err, "login: could not read login page")
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if err != nil {
		return errkit.Wrap(err, "login: could not parse login page")
	}
	form, ok := credentialForm(doc)
	if !ok {
		return errkit.New("login: no credential form found on login page")
	}

	action := strings.TrimSpace(attrOr(form, "action", ""))
	target := loginPage.Request.URL.String()
	if action != "" {
		if resolved, resolveErr := loginPage.Request.URL.Parse(action); resolveErr == nil {
			target = resolved.String()
		}
	}

	method := strings.ToUpper(strings.TrimSpace(attrOr(form, "method", http.MethodPost)))
	if method != http.MethodGet && method != http.MethodPost {
		method = http.MethodPost
	}

	values := l.formValues(form)
	encoded := values.Encode()

	var resp *http.Response
	if method == http.MethodGet {
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		resp, err = l.do(ctx, http.MethodGet, target+sep+encoded, "")
	} else {
		resp, err = l.do(ctx, http.MethodPost, target, encoded)
	}
	if err != nil {
		return errkit.Wrap(err, "login: could not submit credential form")
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return errkit.Newf("login: credentials rejected with status %d", resp.StatusCode)
	}
	if final := resp.Request.URL; final != nil && loginURLPattern.MatchString(final.Path) {
		return errkit.Newf("login: ended back on a login page (%s)", final.Path)
	}
	return nil
}

// do issues a single request through the login client. Redirect following and
// per-hop cookie handling are the client's job (it carries the shared jar).
func (l *HTTPFormLogin) do(ctx context.Context, method, rawurl, body string) (*http.Response, error) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawurl, reader)
	if err != nil {
		return nil, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	retryableReq, err := retryablehttp.FromRequest(req)
	if err != nil {
		return nil, err
	}
	return l.Client.Do(retryableReq)
}

// formValues maps the form's inputs to submission values: password fields get
// the password, the first text-like field gets the username, hidden fields
// (CSRF tokens) are submitted as-is, and everything else keeps its default.
func (l *HTTPFormLogin) formValues(form *goquery.Selection) url.Values {
	values := url.Values{}
	usernamePlaced := false
	form.Find("input").Each(func(_ int, input *goquery.Selection) {
		name := strings.TrimSpace(attrOr(input, "name", ""))
		if name == "" {
			return
		}
		switch typ := strings.ToLower(strings.TrimSpace(attrOr(input, "type", "text"))); typ {
		case "password":
			values.Set(name, l.Password)
		case "hidden":
			values.Set(name, attrOr(input, "value", ""))
		case "submit", "button", "reset", "file", "image", "checkbox", "radio":
			// Only successful (clicked/checked) controls are submitted.
		default:
			if !usernamePlaced {
				values.Set(name, l.Username)
				usernamePlaced = true
			} else if def := attrOr(input, "value", ""); def != "" {
				values.Set(name, def)
			}
		}
	})
	return values
}
