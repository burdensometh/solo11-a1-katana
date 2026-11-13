package common

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/katana/pkg/navigation"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	httputil "github.com/projectdiscovery/utils/http"
	"github.com/stretchr/testify/require"
)

func TestSessionGuardSingleFlight(t *testing.T) {
	var logins atomic.Int32
	guard := NewSessionGuard(func(ctx context.Context, loginURL string) error {
		logins.Add(1)
		time.Sleep(50 * time.Millisecond) // hold the lock so waiters pile up
		return nil
	})
	guard.SetLoginURL("http://target/login")

	const workers = 50
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = guard.EnsureSession(context.Background(), 0)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "worker %d", i)
	}
	require.Equal(t, int32(1), logins.Load(), "exactly one goroutine must log in")
	require.Equal(t, uint64(1), guard.Generation())
}

func TestSessionGuardWaitersReuseSession(t *testing.T) {
	var logins atomic.Int32
	release := make(chan struct{})
	guard := NewSessionGuard(func(ctx context.Context, loginURL string) error {
		logins.Add(1)
		<-release // block until all waiters are queued on the mutex
		return nil
	})
	guard.SetLoginURL("http://target/login")

	first := make(chan error, 1)
	go func() { first <- guard.EnsureSession(context.Background(), 0) }()

	// Give the winner a head start, then pile on waiters.
	time.Sleep(20 * time.Millisecond)
	const waiters = 10
	var wg sync.WaitGroup
	errs := make([]error, waiters)
	for i := 0; i < waiters; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = guard.EnsureSession(context.Background(), 0)
		}(i)
	}
	time.Sleep(50 * time.Millisecond) // let waiters block on the mutex
	close(release)
	wg.Wait()
	require.NoError(t, <-first)
	for i, err := range errs {
		require.NoError(t, err, "waiter %d", i)
	}
	require.Equal(t, int32(1), logins.Load(), "waiters must reuse the winner's session")

	// A caller that observes the new generation does not trigger a login.
	require.NoError(t, guard.EnsureSession(context.Background(), 0))
	require.Equal(t, int32(1), logins.Load(), "stale generation must not re-login")

	// A caller at the current generation logs in again when needed.
	require.NoError(t, guard.EnsureSession(context.Background(), 1))
	require.Equal(t, int32(2), logins.Load())
	require.Equal(t, uint64(2), guard.Generation())
}

func TestSessionGuardCircuitBreaker(t *testing.T) {
	var logins atomic.Int32
	var stops atomic.Int32
	guard := NewSessionGuard(func(ctx context.Context, loginURL string) error {
		logins.Add(1)
		return errors.New("bad credentials")
	}, WithMaxLoginFailures(3))
	guard.SetLoginURL("http://target/login")
	guard.BindStop(func() { stops.Add(1) })

	// Generation never advances, so every call attempts a login.
	err := guard.EnsureSession(context.Background(), 0)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrSessionCircuitOpen)
	require.False(t, guard.Tripped())

	err = guard.EnsureSession(context.Background(), 0)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrSessionCircuitOpen)
	require.False(t, guard.Tripped())

	err = guard.EnsureSession(context.Background(), 0)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrSessionCircuitOpen, "third failure must trip the circuit, got: %v", err)
	require.True(t, guard.Tripped())
	require.Equal(t, int32(1), stops.Load(), "stop must be called exactly once on trip")

	// Further calls fail fast without attempting a login.
	err = guard.EnsureSession(context.Background(), 0)
	require.ErrorIs(t, err, ErrSessionCircuitOpen)
	require.Equal(t, int32(3), logins.Load(), "no login attempts after the circuit opened")
	require.Equal(t, int32(1), stops.Load())
}

func TestSessionGuardConcurrentFailuresTripOnce(t *testing.T) {
	var logins atomic.Int32
	var stops atomic.Int32
	guard := NewSessionGuard(func(ctx context.Context, loginURL string) error {
		logins.Add(1)
		return errors.New("nope")
	}, WithMaxLoginFailures(3))
	guard.SetLoginURL("http://target/login")
	guard.BindStop(func() { stops.Add(1) })

	const workers = 20
	var wg sync.WaitGroup
	var circuitErrs atomic.Int32
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := guard.EnsureSession(context.Background(), 0); errors.Is(err, ErrSessionCircuitOpen) {
				circuitErrs.Add(1)
			}
		}()
	}
	wg.Wait()

	require.Equal(t, int32(3), logins.Load(), "exactly maxFailures login attempts must run")
	require.Equal(t, int32(1), stops.Load(), "stop must fire exactly once")
	require.GreaterOrEqual(t, circuitErrs.Load(), int32(1))
}

func TestSessionGuardSuccessResetsFailures(t *testing.T) {
	var calls atomic.Int32
	guard := NewSessionGuard(func(ctx context.Context, loginURL string) error {
		// Fail the first two attempts, then succeed.
		if calls.Add(1) <= 2 {
			return errors.New("transient")
		}
		return nil
	}, WithMaxLoginFailures(3))
	guard.SetLoginURL("http://target/login")

	require.Error(t, guard.EnsureSession(context.Background(), 0))
	require.Error(t, guard.EnsureSession(context.Background(), 0))
	require.Equal(t, 2, guard.Failures())

	require.NoError(t, guard.EnsureSession(context.Background(), 0))
	require.Equal(t, 0, guard.Failures(), "success resets the failure counter")
	require.Equal(t, uint64(1), guard.Generation())
	require.False(t, guard.Tripped())
}

func TestSessionGuardCancelledContextNotCounted(t *testing.T) {
	guard := NewSessionGuard(func(ctx context.Context, loginURL string) error {
		return errors.New("aborted mid-flight")
	})
	guard.SetLoginURL("http://target/login")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := guard.EnsureSession(ctx, 0)
	require.Error(t, err)
	require.Equal(t, 0, guard.Failures(), "shutdown-induced failures must not count")
	require.False(t, guard.Tripped())
}

func TestSessionGuardNoLoginURL(t *testing.T) {
	guard := NewSessionGuard(func(ctx context.Context, loginURL string) error { return nil })
	err := guard.EnsureSession(context.Background(), 0)
	require.Error(t, err, "missing login URL must be an error")
	require.False(t, guard.Tripped(), "missing URL must not trip the circuit")
}

// loginPageResponse builds a navigation.Response as the standard engine
// would produce it: final request URL after redirects, status and parsed body.
func loginPageResponse(t *testing.T, finalURL string, status int, body string) *navigation.Response {
	t.Helper()
	parsed, err := url.Parse(finalURL)
	require.NoError(t, err)
	httpResp := &http.Response{
		StatusCode: status,
		Header:     http.Header{},
		Request:    &http.Request{URL: parsed},
	}
	resp := &navigation.Response{Resp: httpResp, StatusCode: status, Body: body}
	if body != "" {
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
		require.NoError(t, err)
		resp.Reader = doc
	}
	return resp
}

const loginFormHTML = `<html><body><form id="f" method="post" action="/login">` +
	`<input type="email" name="email"/><input type="password" name="password"/>` +
	`<input type="submit"/></form></body></html>`

func TestIsLoginResponse(t *testing.T) {
	guard := NewSessionGuard(func(ctx context.Context, loginURL string) error { return nil })

	tests := []struct {
		name     string
		reqURL   string
		finalURL string
		status   int
		body     string
		want     bool
	}{
		{"redirected to login", "http://t/app/secret", "http://t/login?next=/app/secret", 200, "", true},
		{"redirected to signin", "http://t/app/secret", "http://t/accounts/signin", 200, "", true},
		{"normal page", "http://t/app/secret", "http://t/app/secret", 200, "<html>ok</html>", false},
		{"requested login page directly", "http://t/login", "http://t/login", 200, loginFormHTML, false},
		{"login form in body (200 rewrite)", "http://t/app/secret", "http://t/app/secret", 200, loginFormHTML, true},
		{"change-password form is not a wall", "http://t/account/pw", "http://t/account/pw", 200,
			`<html><body><form method="post" action="/account/change-password">` +
				`<input type="password" name="new"/></form></body></html>`, false},
		{"no body no redirect", "http://t/app/x", "http://t/app/x", 204, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &navigation.Request{URL: tt.reqURL}
			resp := loginPageResponse(t, tt.finalURL, tt.status, tt.body)
			require.Equal(t, tt.want, guard.IsLoginResponse(req, resp))
		})
	}
}

func TestIsLoginResponseRedirectDisabled(t *testing.T) {
	guard := NewSessionGuard(func(ctx context.Context, loginURL string) error { return nil })

	// With DisableRedirects the client returns the 302 itself: the login
	// target is only visible in the Location header.
	parsed, _ := url.Parse("http://t/app/secret")
	resp := &navigation.Response{
		StatusCode: http.StatusFound,
		Resp: &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"/login"}},
			Request:    &http.Request{URL: parsed},
		},
	}
	req := &navigation.Request{URL: "http://t/app/secret"}
	require.True(t, guard.IsLoginResponse(req, resp))
	require.Equal(t, "http://t/login", guard.LoginURL(), "relative Location must resolve against the request URL")
}

func TestIsLoginResponseLearnsLoginURL(t *testing.T) {
	guard := NewSessionGuard(func(ctx context.Context, loginURL string) error { return nil })
	req := &navigation.Request{URL: "http://t/app/secret"}
	resp := loginPageResponse(t, "http://t/login?next=/app/secret#frag", 200, "")
	require.True(t, guard.IsLoginResponse(req, resp))
	require.Equal(t, "http://t/login?next=/app/secret", guard.LoginURL())
}

func TestIsLoginResponseNilSafety(t *testing.T) {
	guard := NewSessionGuard(func(ctx context.Context, loginURL string) error { return nil })
	req := &navigation.Request{URL: "http://t/x"}
	require.False(t, guard.IsLoginResponse(req, nil))
	require.False(t, guard.IsLoginResponse(req, &navigation.Response{}))
	require.False(t, guard.IsLoginResponse(nil, loginPageResponse(t, "http://t/login", 200, "")))
}

// newLoginClient builds a login HTTP client the way NewShared does for the
// session guard: shared jar on the client, redirects always followed.
func newLoginClient(t *testing.T) (*retryablehttp.Client, *httputil.CookieJar) {
	t.Helper()
	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	require.NoError(t, err)
	t.Cleanup(func() { dialer.Close() })

	jar, err := httputil.NewCookieJar()
	require.NoError(t, err)

	client, _, err := BuildHttpClient(dialer, &types.Options{Timeout: 10, Retries: 1}, nil)
	require.NoError(t, err)
	client.HTTPClient.Jar = jar
	client.HTTPClient.CheckRedirect = nil
	if client.HTTPClient2 != nil {
		client.HTTPClient2.Jar = jar
		client.HTTPClient2.CheckRedirect = nil
	}
	return client, jar
}

// formLab is a minimal form-login web app for HTTPFormLogin tests.
type formLab struct {
	server   *httptest.Server
	posts    atomic.Int32
	lastForm atomic.Value // url.Values of the last POST
}

func newFormLab(t *testing.T, mutate func(w http.ResponseWriter, r *http.Request) bool) *formLab {
	t.Helper()
	lab := &formLab{}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			http.SetCookie(w, &http.Cookie{Name: "csrf_cookie", Value: "c1", Path: "/"})
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body><form method="post" action="/login">`+
				`<input type="hidden" name="csrf" value="tok123"/>`+
				`<input type="email" name="email"/>`+
				`<input type="password" name="password"/>`+
				`<input type="submit" value="go"/></form></body></html>`)
		case http.MethodPost:
			lab.posts.Add(1)
			_ = r.ParseForm()
			lab.lastForm.Store(r.Form)
			if mutate != nil && mutate(w, r) {
				return
			}
			if r.FormValue("email") != "user@example.com" || r.FormValue("password") != "s3cret" {
				http.Error(w, "invalid", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "tok", Path: "/"})
			http.Redirect(w, r, "/app/dashboard", http.StatusFound)
		}
	})
	mux.HandleFunc("/app/dashboard", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value != "tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `<html><body>dashboard</body></html>`)
	})
	lab.server = httptest.NewServer(mux)
	t.Cleanup(lab.server.Close)
	return lab
}

func TestHTTPFormLoginSuccess(t *testing.T) {
	lab := newFormLab(t, nil)
	client, jar := newLoginClient(t)

	login := &HTTPFormLogin{Client: client, Username: "user@example.com", Password: "s3cret"}
	require.NoError(t, login.Login(context.Background(), lab.server.URL+"/login"))

	require.Equal(t, int32(1), lab.posts.Load())
	posted := lab.lastForm.Load().(url.Values)
	require.Equal(t, "user@example.com", posted.Get("email"))
	require.Equal(t, "s3cret", posted.Get("password"))
	require.Equal(t, "tok123", posted.Get("csrf"), "hidden CSRF fields must be submitted")

	parsed, _ := url.Parse(lab.server.URL)
	var names []string
	for _, c := range jar.Cookies(parsed) {
		names = append(names, c.Name)
	}
	require.Contains(t, names, "session", "session cookie must land in the shared jar")
}

func TestHTTPFormLoginRejected(t *testing.T) {
	lab := newFormLab(t, nil)
	client, _ := newLoginClient(t)

	login := &HTTPFormLogin{Client: client, Username: "user@example.com", Password: "wrong"}
	require.Error(t, login.Login(context.Background(), lab.server.URL+"/login"),
		"401 from the login POST must fail the login")
}

func TestHTTPFormLoginBackToLoginPage(t *testing.T) {
	// App that answers a bad login with a redirect back to /login.
	lab := newFormLab(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.FormValue("password") != "s3cret" {
			http.Redirect(w, r, "/login?error=1", http.StatusFound)
			return true
		}
		return false
	})
	client, _ := newLoginClient(t)

	login := &HTTPFormLogin{Client: client, Username: "user@example.com", Password: "wrong"}
	require.Error(t, login.Login(context.Background(), lab.server.URL+"/login"),
		"landing back on the login page must fail the login")
}

func TestHTTPFormLoginNoForm(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>nothing here</body></html>`)
	}))
	t.Cleanup(server.Close)

	client, _ := newLoginClient(t)
	login := &HTTPFormLogin{Client: client, Username: "u", Password: "p"}
	require.Error(t, login.Login(context.Background(), server.URL), "missing credential form must fail")
}
