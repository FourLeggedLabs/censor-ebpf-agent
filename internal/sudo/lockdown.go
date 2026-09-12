package sudo

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

const (
	defaultSudoersFile = "/etc/sudoers.d/zz-censor-lockdown"
	defaultStateFile   = "/etc/sudoers.d/.censor-lockdown-state"
)

// WatchEvent is emitted when a sudo-like exec is observed (userspace hook).
type WatchEvent struct {
	PID  uint32
	Comm string
	Argv []string
}

// IsSudoComm reports whether comm looks like sudo.
func IsSudoComm(comm string) bool {
	base := filepath.Base(comm)
	return base == "sudo" || base == "sudoedit"
}

// Lockdown installs a restrictive sudoers drop-in for the runner user.
// Paths are overridable for tests.
type Lockdown struct {
	SudoersFile string
	StateFile   string
	Username    string
	AllowCmds   []string
}

func (l *Lockdown) paths() (sudoers, state string) {
	sudoers = l.SudoersFile
	if sudoers == "" {
		sudoers = defaultSudoersFile
	}
	state = l.StateFile
	if state == "" {
		state = defaultStateFile
	}
	return sudoers, state
}

// Enable writes sudoers lockdown and records state for Disable.
func (l *Lockdown) Enable() error {
	sudoers, state := l.paths()
	userName := l.Username
	if userName == "" {
		u, err := user.Current()
		if err != nil {
			return err
		}
		userName = u.Username
		if userName == "root" {
			for _, cand := range []string{"runner", "github", "ci"} {
				if _, err := user.Lookup(cand); err == nil {
					userName = cand
					break
				}
			}
		}
	}
	if strings.ContainsAny(userName, " ,#\n\t") {
		return fmt.Errorf("unsafe username %q", userName)
	}
	var b strings.Builder
	b.WriteString("# Managed by censor — do not edit\n")
	b.WriteString("Defaults:" + userName + " !authenticate\n")
	if len(l.AllowCmds) == 0 {
		b.WriteString(userName + " ALL=(ALL) !ALL\n")
	} else {
		b.WriteString(userName + " ALL=(root) NOPASSWD: ")
		b.WriteString(strings.Join(l.AllowCmds, ", "))
		b.WriteString("\n")
	}
	if err := os.WriteFile(sudoers, []byte(b.String()), 0o440); err != nil {
		return err
	}
	return os.WriteFile(state, []byte(userName+"\n"), 0o600)
}

// Disable removes the lockdown file if state exists.
func (l *Lockdown) Disable() error {
	sudoers, state := l.paths()
	_ = os.Remove(sudoers)
	_ = os.Remove(state)
	return nil
}
