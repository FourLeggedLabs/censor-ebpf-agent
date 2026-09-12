package sudo_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FourLeggedLabs/censor-ebpf-agent/internal/sudo"
)

func TestIsSudoComm(t *testing.T) {
	if !sudo.IsSudoComm("sudo") || !sudo.IsSudoComm("/usr/bin/sudo") {
		t.Fatal("expected sudo match")
	}
	if sudo.IsSudoComm("curl") {
		t.Fatal("curl should not match")
	}
}

func TestLockdownRoundTrip(t *testing.T) {
	dir := t.TempDir()
	l := &sudo.Lockdown{
		SudoersFile: filepath.Join(dir, "zz-censor"),
		StateFile:   filepath.Join(dir, ".state"),
		Username:    "runner",
		AllowCmds:   []string{"/usr/bin/docker"},
	}
	if err := l.Enable(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(l.SudoersFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "NOPASSWD: /usr/bin/docker") {
		t.Fatalf("%s", b)
	}
	if err := l.Disable(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(l.SudoersFile); !os.IsNotExist(err) {
		t.Fatalf("sudoers still present: %v", err)
	}
}
