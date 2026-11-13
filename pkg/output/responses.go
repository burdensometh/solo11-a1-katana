package output

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/utils/errkit"
	urlutil "github.com/projectdiscovery/utils/url"
)

func getResponseHash(URL string) string {
	hash := sha1.Sum([]byte(URL))
	return hex.EncodeToString(hash[:])
}

func (w *StandardWriter) formatResult(result *Result) ([]byte, error) {
	builder := &bytes.Buffer{}

	builder.WriteString(result.Request.URL)
	builder.WriteString("\n\n\n")

	builder.WriteString(result.Request.Raw)

	builder.WriteString("\n\n")

	builder.WriteString(result.Response.Raw)

	return builder.Bytes(), nil
}

func getResponseHost(URL string) (string, error) {
	u, err := urlutil.Parse(URL)
	if err != nil {
		return "", err
	}
	return filepath.Clean(strings.ReplaceAll(u.Host, ":", "_")), nil
}

func createHostDir(storeResponseFolder, domain string) string {
	_ = os.MkdirAll(filepath.Join(storeResponseFolder, domain), os.ModePerm)
	return filepath.Join(storeResponseFolder, domain)
}

func getResponseFile(storeResponseFolder, URL string) (string, *fileWriter, error) {
	domain, err := getResponseHost(URL)
	if err != nil {
		return "", nil, err
	}
	fileName := getResponseFileName(storeResponseFolder, domain, URL)
	output, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return "", nil, errkit.Wrap(err, "output: could not create output file")
	}

	return fileName, newOneShotFileWriter(output), nil
}

func getResponseFileName(storeResponseFolder, domain, URL string) string {
	folder := createHostDir(storeResponseFolder, domain)
	file := getResponseHash(URL) + ".txt"
	return filepath.Join(folder, file)
}

// updateIndex appends an entry to the response index through the writer's
// single persistent file handle, avoiding an open/close per result.
func (w *StandardWriter) updateIndex(result *Result) error {
	if w.indexFile == nil {
		return nil
	}

	builder := &bytes.Buffer{}

	domain, err := getResponseHost(result.Request.URL)
	if err != nil {
		return err
	}

	builder.WriteString(getResponseFileName(w.storeResponseDir, domain, result.Request.URL))
	builder.WriteRune(' ')
	builder.WriteString(result.Request.URL)
	builder.WriteRune(' ')
	builder.WriteString("(" + result.Response.Resp.Status + ")")

	if err := w.indexFile.Write(builder.Bytes()); err != nil {
		return errkit.Wrap(err, "output: could not update index")
	}

	return nil
}
