/*
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
:                                                                               :
:   █▀ █ █▀▀   ·   Blazing-fast pentesting suite                                :
:   ▄█ █ █▀    ·   BSD 3-Clause License                                         :
:                                                                               :
:   (c) 2022-2025 vmfunc (vmfunc), xyzeva,                        :
:                 lunchcat alumni & contributors                                :
:                                                                               :
·━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━·
*/

package logger

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Logger manages buffered file writers for efficient logging.
// File handles are kept open and writes are buffered to minimize I/O overhead.
type Logger struct {
	mu      sync.RWMutex
	writers map[string]*bufio.Writer
	files   map[string]*os.File
}

var defaultLogger = &Logger{
	writers: make(map[string]*bufio.Writer),
	files:   make(map[string]*os.File),
}

// Init creates the log directory if it doesn't exist.
func Init(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.Mkdir(dir, 0o755); err != nil {
			return err
		}
	}
	return nil
}

// getWriter returns a buffered writer for the given file path, creating it if needed.
func (l *Logger) getWriter(path string) (*bufio.Writer, error) {
	l.mu.RLock()
	w, exists := l.writers[path]
	l.mu.RUnlock()

	if exists {
		return w, nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Double-check after acquiring write lock
	if w, exists = l.writers[path]; exists {
		return w, nil
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o666)
	if err != nil {
		return nil, err
	}

	w = bufio.NewWriter(f)
	l.writers[path] = w
	l.files[path] = f

	return w, nil
}

// write writes text to the specified log file using buffered I/O.
func (l *Logger) write(path, text string) error {
	w, err := l.getWriter(path)
	if err != nil {
		return err
	}

	l.mu.Lock()
	_, err = w.WriteString(text)
	l.mu.Unlock()

	return err
}

// Flush flushes all buffered writers to disk.
func (l *Logger) Flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, w := range l.writers {
		if err := w.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// Close flushes and closes all open file handles.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	var firstErr error
	for path, w := range l.writers {
		if err := w.Flush(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := l.files[path].Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	l.writers = make(map[string]*bufio.Writer)
	l.files = make(map[string]*os.File)

	return firstErr
}

// CreateFile initializes a log file for the given URL and writes the header.
func CreateFile(logFiles *[]string, url string, dir string) error {
	sanitizedURL := strings.Split(url, "://")[1]
	path := filepath.Join(dir, sanitizedURL+".log")

	header := fmt.Sprintf("       _____________\n__________(_)__  __/\n__  ___/_  /__  /_  \n_(__  )_  / _  __/  \n/____/ /_/  /_/    \n\nsif log file for %s\nhttps://sif.sh\n\n", url)

	if err := defaultLogger.write(path, header); err != nil {
		return err
	}

	*logFiles = append(*logFiles, path)
	return nil
}

// Write appends text to the log file for the given URL.
func Write(url string, dir string, text string) error {
	path := filepath.Join(dir, url+".log")
	return defaultLogger.write(path, text)
}

// WriteHeader writes a section header to the log file.
func WriteHeader(url string, dir string, scan string) error {
	return Write(url, dir, fmt.Sprintf("\n\n--------------\nStarting %s\n--------------\n", scan))
}

// Flush flushes all buffered log data to disk.
func Flush() error {
	return defaultLogger.Flush()
}

// Close flushes and closes all log files. Should be called before program exit.
func Close() error {
	return defaultLogger.Close()
}
