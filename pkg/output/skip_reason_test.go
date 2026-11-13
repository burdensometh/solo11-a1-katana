package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/katana/pkg/navigation"
	"github.com/projectdiscovery/katana/pkg/utils/extensions"
	"github.com/stretchr/testify/require"
)

// TestWriteSkipReasonJSON verifies that an intercepted result serializes the
// scope reason code under skip_reason, while a normal result omits the field.
func TestWriteSkipReasonJSON(t *testing.T) {
	outFile := filepath.Join(t.TempDir(), "out.jsonl")
	writer, err := New(Options{
		JSON:               true,
		OutputFile:         outFile,
		ExtensionValidator: extensions.NewValidator(nil, nil, true),
	})
	require.NoError(t, err)

	require.NoError(t, writer.Write(&Result{
		Request:    &navigation.Request{URL: "http://example.com/blocked"},
		SkipReason: "scope_out_of_bound",
		Error:      "out of scope",
	}))
	require.NoError(t, writer.Write(&Result{
		Request: &navigation.Request{URL: "http://example.com/ok"},
	}))
	require.NoError(t, writer.Close())

	data, err := os.ReadFile(outFile)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], `"skip_reason":"scope_out_of_bound"`)
	require.NotContains(t, lines[1], "skip_reason")
}
