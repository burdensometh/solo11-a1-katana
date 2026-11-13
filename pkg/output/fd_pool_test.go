package output

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/katana/pkg/navigation"
	"github.com/projectdiscovery/katana/pkg/utils/extensions"
	"github.com/stretchr/testify/require"
)

// openFDs counts the file descriptors this process currently holds.
func openFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	return len(entries)
}

// Writing thousands of results must keep the number of open output handles
// bounded instead of opening a fresh file per result. The old per-result
// open/close path briefly held a new descriptor on every write; the pooled
// writer opens each destination file exactly once.
func TestFieldWriterDoesNotLeakFileDescriptors(t *testing.T) {
	dir := t.TempDir()
	fieldDir := filepath.Join(dir, "fields")
	writer, err := New(Options{
		StoreFields:        "url",
		StoreFieldDir:      fieldDir,
		ExtensionValidator: extensions.NewValidator(nil, nil, true),
	})
	require.NoError(t, err)

	baseline := openFDs(t)

	const total = 3000
	for i := 0; i < total; i++ {
		require.NoError(t, writer.Write(&Result{
			Request: &navigation.Request{URL: fmt.Sprintf("https://example.com/p/%d", i)},
		}))
	}

	// Only one destination field file exists, so at most one extra output
	// descriptor should be open relative to baseline (allowing slack for
	// runtime-internal fds unrelated to output).
	during := openFDs(t)
	require.LessOrEqual(t, during-baseline, 3, "fd count grew by %d; expected a single pooled handle", during-baseline)

	require.NoError(t, writer.Close())

	// After Close the pooled handle must be released back to baseline.
	after := openFDs(t)
	require.LessOrEqual(t, after-baseline, 1, "handle not released after Close")

	data, err := os.ReadFile(filepath.Join(fieldDir, "https_example.com_url.txt"))
	require.NoError(t, err)
	lines := 0
	for _, b := range data {
		if b == '\n' {
			lines++
		}
	}
	require.Equal(t, total, lines)
}
