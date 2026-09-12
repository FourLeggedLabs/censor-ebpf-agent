package events

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	agentv1 "github.com/FourLeggedLabs/protos/gen/go/censor/agent/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const DefaultLogPath = "/var/log/censor/agent.ndjson"

// Logger writes exclusive protojson NDJSON AgentEvent lines.
type Logger struct {
	mu   sync.Mutex
	file *os.File
	path string
}

// Open creates or truncates path with mode 0600, directory 0700, and takes an exclusive flock.
func Open(path string) (*Logger, error) {
	if path == "" {
		path = DefaultLogPath
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("flock: %w", err)
	}
	return &Logger{file: f, path: path}, nil
}

// Path returns the log file path.
func (l *Logger) Path() string { return l.path }

// WriteEvent appends one protojson line.
func (l *Logger) WriteEvent(ev *agentv1.AgentEvent) error {
	b, err := protojson.Marshal(ev)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.file.Write(append(b, '\n')); err != nil {
		return err
	}
	return l.file.Sync()
}

// Close releases the flock and closes the file.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	err := l.file.Close()
	l.file = nil
	return err
}

// ReadFile returns the current log bytes (for upload); holds the write lock briefly.
func (l *Logger) ReadFile() ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.file.Sync(); err != nil {
		return nil, err
	}
	return os.ReadFile(l.path)
}
