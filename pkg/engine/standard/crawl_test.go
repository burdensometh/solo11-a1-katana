package standard

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestCrawlStatsAlignWithOutput crawls a test server end to end and verifies
// that every enqueued request is accounted for in exactly one stats bucket:
// output, redirect, parse failure, or out-of-scope discard.
func TestCrawlStatsAlignWithOutput(t *testing.T) {
	// a guaranteed-closed port so one link fails to connect (parse failure)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedPort := l.Addr().(*net.TCPAddr).Port
	require.NoError(t, l.Close())

	var imageHits atomic.Int64
	mux := http.NewServeMux()
	var closedURL string
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// distinct body; links exercising every outcome bucket
		fmt.Fprintf(w, `<html><body>root`+
			`<a href="/page1">1</a><a href="/page2">2</a>`+
			`<a href="/redirect">r</a><a href="/image.png">i</a>`+
			`<a href="%s">closed</a></body></html>`, closedURL)
	})
	mux.HandleFunc("/page1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>page one</body></html>`))
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>page two</body></html>`))
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/page1")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte(`<html><body>redirect body</body></html>`))
	})
	mux.HandleFunc("/image.png", func(w http.ResponseWriter, r *http.Request) {
		imageHits.Add(1)
		_, _ = w.Write([]byte("png"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	closedURL = fmt.Sprintf("http://127.0.0.1:%d/closed", closedPort)

	options, err := types.NewCrawlerOptions(&types.Options{
		MaxDepth:            2,
		FieldScope:          "fqdn",
		BodyReadSize:        math.MaxInt,
		Timeout:             5,
		Concurrency:         4,
		Strategy:            "depth-first",
		DisableRedirects:    true, // 302 response stays with the crawler
		DisableUniqueFilter: true, // keep content dedup out of the equation
	})
	require.NoError(t, err)
	defer func() { _ = options.Close() }()

	crawler, err := New(options)
	require.NoError(t, err)
	require.NoError(t, crawler.Crawl(srv.URL))

	snap := options.Stats().Snapshot()
	require.Equal(t, int64(6), snap.Enqueued, "seed + 5 discovered links")
	require.Equal(t, int64(3), snap.Output, "/, /page1, /page2")
	require.Equal(t, int64(1), snap.Redirect, "/redirect")
	require.Equal(t, int64(1), snap.ParseFailed, "connection refused")
	require.Equal(t, int64(1), snap.OutOfScope, "/image.png dropped by extension filter")
	require.Equal(t, snap.Enqueued, snap.Processed(),
		"output+redirect+parseFailed+outOfScope must equal enqueued")

	require.Equal(t, int64(0), imageHits.Load(), "discarded URL must never be fetched")

	// every in-scope fetched result is written to output, discarded ones are not
	require.Equal(t, snap.Output+snap.Redirect+snap.ParseFailed, options.OutputWriter.GetResultCount())
}
