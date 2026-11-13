package output

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/katana/pkg/navigation"
	"github.com/projectdiscovery/katana/pkg/utils/extensions"
	"github.com/stretchr/testify/require"
)

// A persistent writer must keep the same file handle open and stream every
// write through it, appending a newline per record.
func TestFileWriterPersistentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.txt")
	fw, err := newFileOutputWriter(path)
	require.NoError(t, err)

	require.NoError(t, fw.Write([]byte("first")))
	require.NoError(t, fw.Write([]byte("second")))
	require.NoError(t, fw.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "first\nsecond\n", string(data))
}

// Every 1000 writes the buffer must be flushed to disk without waiting for
// Close, so a slow crawl still lands batches on the underlying file.
func TestFileWriterFlushAtWriteCount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "count.txt")
	fw, err := newFileOutputWriter(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = fw.Close() })

	for i := 0; i < flushAtWrites-1; i++ {
		require.NoError(t, fw.Write([]byte("x")))
	}
	// The batch boundary has not been reached yet: nothing guaranteed on disk.
	// Crossing it must force a flush.
	require.NoError(t, fw.Write([]byte("x")))

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Greater(t, info.Size(), int64(0), "expected a flush after %d writes", flushAtWrites)
}

// The time-based flusher must push buffered data out even when the write
// count never reaches the threshold.
func TestFileWriterFlushOnInterval(t *testing.T) {
	previous := flushInterval
	flushInterval = 50 * time.Millisecond
	t.Cleanup(func() { flushInterval = previous })

	path := filepath.Join(t.TempDir(), "interval.txt")
	fw, err := newFileOutputWriter(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = fw.Close() })

	require.NoError(t, fw.Write([]byte("periodic")))

	require.Eventually(t, func() bool {
		info, err := os.Stat(path)
		return err == nil && info.Size() > 0
	}, time.Second, 10*time.Millisecond, "expected background flusher to write within the interval")
}

// Close must perform a final flush so no record is lost on a clean exit,
// even when neither flush threshold was reached.
func TestFileWriterCloseFlushesRemainingBuffer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "final.txt")
	fw, err := newFileOutputWriter(path)
	require.NoError(t, err)

	require.NoError(t, fw.Write([]byte("only-record")))
	require.NoError(t, fw.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "only-record\n", string(data))

	// Closing twice must be safe and not panic.
	require.NoError(t, fw.Close())
}

// Concurrent crawler workers share one writer; all records must survive.
func TestFileWriterConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.txt")
	fw, err := newFileOutputWriter(path)
	require.NoError(t, err)

	const goroutines = 16
	const perGoroutine = 200

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				_ = fw.Write([]byte("record"))
			}
		}()
	}
	wg.Wait()
	require.NoError(t, fw.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	expected := goroutines * perGoroutine
	for i := 0; i < expected; i++ {
		require.True(t, len(data) >= len("record\n"))
	}
	require.Equal(t, expected*len("record\n"), len(string(data)))
}

// Append mode must preserve pre-existing content instead of truncating it.
func TestAppendFileWriterPreservesExistingContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "append.txt")
	require.NoError(t, os.WriteFile(path, []byte("existing\n"), 0644))

	fw, err := newAppendFileOutputWriter(path)
	require.NoError(t, err)
	require.NoError(t, fw.Write([]byte("added")))
	require.NoError(t, fw.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "existing\nadded\n", string(data))
}

// A full StandardWriter run with stored fields must reuse a single open
// handle per field file instead of opening/closing it for every result,
// and Close must flush everything to disk.
func TestStandardWriterPersistentFieldFiles(t *testing.T) {
	dir := t.TempDir()
	fieldDir := filepath.Join(dir, "fields")
	options := Options{
		StoreFields:        "url",
		StoreFieldDir:      fieldDir,
		ExtensionValidator: extensions.NewValidator(nil, nil, true),
	}
	writer, err := New(options)
	require.NoError(t, err)
	sw := writer.(*StandardWriter)

	const total = 50
	for i := 0; i < total; i++ {
		result := &Result{
			Request: &navigation.Request{URL: "https://example.com/path?a=1"},
		}
		require.NoError(t, writer.Write(result))
	}

	// Exactly one persistent writer should back the single field file.
	sw.fieldWritersMu.Lock()
	require.Len(t, sw.fieldWriters, 1)
	sw.fieldWritersMu.Unlock()

	require.NoError(t, writer.Close())

	entries, err := os.ReadDir(fieldDir)
	require.NoError(t, err)
	require.Len(t, entries, 1)

	data, err := os.ReadFile(filepath.Join(fieldDir, entries[0].Name()))
	require.NoError(t, err)
	lines := 0
	for _, line := range splitLines(string(data)) {
		if line != "" {
			lines++
		}
	}
	require.Equal(t, total, lines)
}

// The response index must be written through one persistent handle and all
// entries must be present after Close, including in additive custom dirs.
func TestStandardWriterPersistentIndexFile(t *testing.T) {
	dir := t.TempDir()
	customDir := filepath.Join(dir, "responses")
	require.NoError(t, os.MkdirAll(customDir, 0755))
	indexPath := filepath.Join(customDir, indexFile)
	require.NoError(t, os.WriteFile(indexPath, []byte("preexisting-entry\n"), 0644))

	options := Options{
		StoreResponse:      true,
		StoreResponseDir:   customDir,
		JSON:               true,
		ExtensionValidator: extensions.NewValidator(nil, nil, true),
	}
	writer, err := New(options)
	require.NoError(t, err)
	sw := writer.(*StandardWriter)
	require.NotNil(t, sw.indexFile)

	result := &Result{
		Request: &navigation.Request{URL: "https://example.com/page", Raw: "GET /page"},
		Response: &navigation.Response{
			Resp: &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Request: &http.Request{URL: urlMustParse(t, "https://example.com/page")}},
			Raw:  "HTTP/1.1 200 OK",
			Body: "body",
		},
	}
	require.NoError(t, writer.Write(result))
	require.NoError(t, writer.Close())

	data, err := os.ReadFile(indexPath)
	require.NoError(t, err)
	content := string(data)
	require.Contains(t, content, "preexisting-entry")
	require.Contains(t, content, "https://example.com/page")
	require.Contains(t, content, "(200 OK)")
}

func urlMustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	return parsed
}

func splitLines(value string) []string {
	var lines []string
	current := ""
	for _, r := range value {
		if r == '\n' {
			lines = append(lines, current)
			current = ""
			continue
		}
		current += string(r)
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}
