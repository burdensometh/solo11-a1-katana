package standard

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/katana/pkg/engine/common"
	"github.com/projectdiscovery/katana/pkg/engine/parser"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/projectdiscovery/katana/pkg/utils/extensions"
	"github.com/projectdiscovery/katana/pkg/utils/filters"
	"github.com/projectdiscovery/katana/pkg/utils/scope"
	"github.com/stretchr/testify/require"
)

// collectWriter captures crawl results for assertions.
type collectWriter struct {
	mu      sync.Mutex
	results []*output.Result
}

func (w *collectWriter) Close() error { return nil }
func (w *collectWriter) Write(r *output.Result) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.results = append(w.results, r)
	return nil
}
func (w *collectWriter) WriteErr(_ *output.Error) error { return nil }
func (w *collectWriter) GetResultCount() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return int64(len(w.results))
}

func (w *collectWriter) bodies() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var sb strings.Builder
	for _, r := range w.results {
		if r.Response != nil {
			sb.WriteString(r.Response.Body)
			sb.WriteString("\n---\n")
		}
	}
	return sb.String()
}

func (w *collectWriter) loginPageResults() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, r := range w.results {
		if r.Response != nil && strings.Contains(r.Response.Body, `id="login-form"`) {
			n++
		}
	}
	return n
}

// expiryLab is a cookie-gated mini app whose session token rotates when
// /app/trigger-expiry is fetched, simulating a session that dies mid-crawl.
type expiryLab struct {
	server     *httptest.Server
	token      atomic.Value // string
	loginPosts atomic.Int32
	pages      int32
}

const (
	labUser  = "user@example.com"
	labPass  = "s3cret"
	labCSRF  = "tok123"
	markerA  = "SECRET_PAGE_MARKER"
	markerB  = "AFTER_EXPIRY_MARKER"
	loginFrm = `<html><body><form id="login-form" method="post" action="/login">` +
		`<input type="hidden" name="csrf" value="` + labCSRF + `"/>` +
		`<input type="email" name="email"/><input type="password" name="password"/>` +
		`<input type="submit"/></form></body></html>`
)

func newExpiryLab(t *testing.T, pages int) *expiryLab {
	t.Helper()
	lab := &expiryLab{pages: int32(pages)}
	lab.token.Store("tok1")

	authed := func(r *http.Request) bool {
		c, err := r.Cookie("session")
		return err == nil && c.Value == lab.token.Load().(string)
	}
	wall := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusFound)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, loginFrm)
		case http.MethodPost:
			lab.loginPosts.Add(1)
			_ = r.ParseForm()
			if r.FormValue("email") != labUser || r.FormValue("password") != labPass || r.FormValue("csrf") != labCSRF {
				http.Error(w, "invalid credentials", http.StatusUnauthorized)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: lab.token.Load().(string), Path: "/"})
			http.Redirect(w, r, "/", http.StatusFound)
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if !authed(r) {
			wall(w, r)
			return
		}
		http.Redirect(w, r, "/app/dashboard", http.StatusFound)
	})
	mux.HandleFunc("/app/dashboard", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			wall(w, r)
			return
		}
		var sb strings.Builder
		sb.WriteString(`<html><body><h1>dashboard</h1>`)
		sb.WriteString(`<a href="/app/secret">secret</a>`)
		sb.WriteString(`<a href="/app/trigger-expiry">trigger</a>`)
		for i := 0; i < int(lab.pages); i++ {
			fmt.Fprintf(&sb, `<a href="/app/p%d">p%d</a>`, i, i)
		}
		sb.WriteString(`</body></html>`)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, sb.String())
	})
	mux.HandleFunc("/app/secret", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			wall(w, r)
			return
		}
		fmt.Fprintf(w, `<html><body><p>%s</p></body></html>`, markerA)
	})
	mux.HandleFunc("/app/trigger-expiry", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			wall(w, r)
			return
		}
		// The session dies here: every in-flight and subsequent request with
		// the old cookie hits the login wall.
		lab.token.CompareAndSwap("tok1", "tok2")
		fmt.Fprint(w, `<html><body><a href="/app/after">after</a></body></html>`)
	})
	mux.HandleFunc("/app/after", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			wall(w, r)
			return
		}
		fmt.Fprintf(w, `<html><body><p>%s</p></body></html>`, markerB)
	})
	// Catch-all for the /app/pN content pages linked from the dashboard.
	mux.HandleFunc("/app/", func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			wall(w, r)
			return
		}
		n := strings.TrimPrefix(r.URL.Path, "/app/p")
		fmt.Fprintf(w, `<html><body><p>page-%s-content</p></body></html>`, n)
	})
	lab.server = httptest.NewServer(mux)
	t.Cleanup(lab.server.Close)
	return lab
}

func newTestCrawlerOptions(t *testing.T, writer output.Writer, concurrency int, creds string) *types.CrawlerOptions {
	t.Helper()
	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	require.NoError(t, err)
	t.Cleanup(func() { dialer.Close() })

	scopeManager, err := scope.NewManager(nil, nil, "", true)
	require.NoError(t, err)
	itemFilter, err := filters.NewSimple()
	require.NoError(t, err)
	responseParser := parser.NewResponseParser()
	responseParser.InitWithOptions(&parser.Options{})

	return &types.CrawlerOptions{
		OutputWriter:        writer,
		Parser:              responseParser,
		UniqueFilter:        itemFilter,
		ScopeManager:        scopeManager,
		ExtensionsValidator: extensions.NewValidator(nil, nil, true),
		Dialer:              dialer,
		Options: &types.Options{
			MaxDepth:        3,
			Concurrency:     concurrency,
			Strategy:        "depth-first",
			Timeout:         10,
			Retries:         1,
			BodyReadSize:    4 << 20,
			AuthCredentials: creds,
		},
	}
}

func TestSessionExpiryMidCrawlSequential(t *testing.T) {
	lab := newExpiryLab(t, 0)
	writer := &collectWriter{}

	crawler, err := New(newTestCrawlerOptions(t, writer, 1, labUser+":"+labPass))
	require.NoError(t, err)
	require.NoError(t, crawler.Crawl(lab.server.URL))

	require.Equal(t, int32(2), lab.loginPosts.Load(),
		"initial login plus exactly one re-login after the mid-crawl expiry")
	bodies := writer.bodies()
	require.Contains(t, bodies, markerA, "content fetched before the expiry must be present")
	require.Contains(t, bodies, markerB, "content behind the expiry must be fetched after re-login")
	require.Zero(t, writer.loginPageResults(), "no login page may leak into the results")
}

func TestSessionExpiryMidCrawlConcurrent(t *testing.T) {
	lab := newExpiryLab(t, 20)
	writer := &collectWriter{}

	crawler, err := New(newTestCrawlerOptions(t, writer, 8, labUser+":"+labPass))
	require.NoError(t, err)
	require.NoError(t, crawler.Crawl(lab.server.URL))

	require.Equal(t, int32(2), lab.loginPosts.Load(),
		"concurrent workers hitting the wall must share one re-login")
	bodies := writer.bodies()
	require.Contains(t, bodies, markerA)
	require.Contains(t, bodies, markerB)
	for i := 0; i < 20; i++ {
		require.Contains(t, bodies, fmt.Sprintf("page-%d-content", i))
	}
	require.Zero(t, writer.loginPageResults(), "no login page may leak into the results")
}

func TestSessionReloginFailsStopsCrawl(t *testing.T) {
	lab := newExpiryLab(t, 0)
	writer := &collectWriter{}

	// Wrong password: every login attempt is rejected with 401.
	crawler, err := New(newTestCrawlerOptions(t, writer, 4, labUser+":wrong"))
	require.NoError(t, err)
	err = crawler.Crawl(lab.server.URL)
	require.Error(t, err)
	require.ErrorIs(t, err, common.ErrSessionCircuitOpen)
	require.Equal(t, int32(common.DefaultMaxLoginFailures), lab.loginPosts.Load(),
		"crawl must stop after the configured number of failed re-logins")
	require.Zero(t, writer.loginPageResults(), "no login page may leak into the results")
	require.NotContains(t, writer.bodies(), markerA, "protected content must not appear")
}
