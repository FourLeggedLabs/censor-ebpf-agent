package events_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FourLeggedLabs/censor-ebpf-agent/internal/events"
	agentv1 "github.com/FourLeggedLabs/protos/gen/go/censor/agent/v1"
)

func TestExclusiveLogger(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.ndjson")
	l, err := events.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}

	if _, err := events.Open(path); err == nil {
		t.Fatal("expected flock failure on second open")
	}

	if err := l.WriteEvent(&agentv1.AgentEvent{
		Type:   agentv1.EventType_EVENT_TYPE_SUDO,
		Action: agentv1.Action_ACTION_ALLOW,
		Pid:    1,
		Comm:   "sudo",
	}); err != nil {
		t.Fatal(err)
	}
	b, err := l.ReadFile()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "EVENT_TYPE_SUDO") {
		t.Fatalf("%s", b)
	}
}
