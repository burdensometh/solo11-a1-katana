package output

import (
	"bufio"
	"errors"
	"os"
	"sync"
	"time"
)

const (
	// flushAtWrites forces a flush after this many writes since the last
	// flush, so a slow crawl still lands results on disk regularly.
	flushAtWrites = 1000
	// bufferedWriterSize keeps many small writes coalesced into one syscall.
	bufferedWriterSize = 64 * 1024
)

// flushInterval forces a flush once this much time has elapsed since the
// last flush, even when the write counter has not been reached. It is a
// variable so tests can shorten it; production code keeps the 2s default.
var flushInterval = 2 * time.Second

// fileWriter is a concurrent file based output writer. It keeps a single
// file handle open for its whole lifetime and coalesces writes through a
// buffered writer that is flushed every flushAtWrites writes or every
// flushInterval. On a crash only the data still held in the buffer (at
// most the last flush batch) is lost.
type fileWriter struct {
	file   *os.File
	writer *bufio.Writer

	mu        sync.Mutex
	writes    int
	lastFlush time.Time
	autoFlush bool
	stop      chan struct{}
	stopped   chan struct{}
	closeOnce sync.Once
}

// newFileOutputWriter opens a persistent, auto-flushing buffered writer for
// a file. The file is created (or truncated) once, at startup, and the
// underlying handle stays open until Close is called.
func newFileOutputWriter(file string) (*fileWriter, error) {
	output, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}
	return newBufferedFileWriter(output, true), nil
}

// newAppendFileOutputWriter opens a persistent auto-flushing writer in
// append mode, used for additive files such as the response index.
func newAppendFileOutputWriter(file string) (*fileWriter, error) {
	output, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return newBufferedFileWriter(output, true), nil
}

// newOneShotFileWriter wraps a freshly opened file without the background
// flusher. It is used for response body files that receive a single write
// and are closed immediately afterwards.
func newOneShotFileWriter(output *os.File) *fileWriter {
	return newBufferedFileWriter(output, false)
}

func newBufferedFileWriter(output *os.File, autoFlush bool) *fileWriter {
	w := &fileWriter{
		file:      output,
		writer:    bufio.NewWriterSize(output, bufferedWriterSize),
		lastFlush: time.Now(),
		autoFlush: autoFlush,
	}
	if autoFlush {
		w.stop = make(chan struct{})
		w.stopped = make(chan struct{})
		go w.flushLoop()
	}
	return w
}

// Write appends data followed by a newline to the underlying file.
func (w *fileWriter) Write(data []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, err := w.writer.Write(data); err != nil {
		return err
	}
	if err := w.writer.WriteByte('\n'); err != nil {
		return err
	}

	w.writes++
	if w.autoFlush && (w.writes >= flushAtWrites || time.Since(w.lastFlush) >= flushInterval) {
		if err := w.flushLocked(); err != nil {
			return err
		}
	}
	return nil
}

// flushLoop flushes the buffer periodically so low-volume output does not
// sit in memory for the whole crawl.
func (w *fileWriter) flushLoop() {
	defer close(w.stopped)
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-ticker.C:
			w.mu.Lock()
			_ = w.flushLocked()
			w.mu.Unlock()
		}
	}
}

// flushLocked writes the buffer to disk. The caller must hold w.mu.
func (w *fileWriter) flushLocked() error {
	if err := w.writer.Flush(); err != nil {
		return err
	}
	w.writes = 0
	w.lastFlush = time.Now()
	return nil
}

// Close stops the background flusher, forces a final flush and closes the
// underlying file handle.
func (w *fileWriter) Close() error {
	var err error
	w.closeOnce.Do(func() {
		if w.autoFlush {
			close(w.stop)
			<-w.stopped
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		if flushErr := w.writer.Flush(); flushErr != nil {
			err = flushErr
		}
		//nolint:errcheck // we don't care whether sync failed or succeeded.
		w.file.Sync()
		if closeErr := w.file.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	})
	return err
}
