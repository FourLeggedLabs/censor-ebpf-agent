//go:build linux

package ebpfutil

import (
	"fmt"
	"net/netip"
	"sync"
)

// Linux attach will load generated bpf objects once bpf2go artifacts exist.
// Until then, behave like a soft stub so CI unit tests compile on linux runners
// without CAP_BPF; real load lives behind LoadAndAttach when objects are present.

var (
	mu     sync.Mutex
	active bool
)

// AttachFirewall attempts to load/attach programs; returns error if objects missing.
func AttachFirewall(auditMode bool) error {
	mu.Lock()
	defer mu.Unlock()
	if err := loadAndAttach(auditMode); err != nil {
		return err
	}
	active = true
	return nil
}

func DetachFirewall() error {
	mu.Lock()
	defer mu.Unlock()
	if !active {
		return nil
	}
	active = false
	return unload()
}

func AllowIP(addr netip.Addr) error {
	if !addr.Is4() {
		return nil
	}
	return allowV4(addr)
}

func loadAndAttach(auditMode bool) error {
	return fmt.Errorf("bpf objects not generated; run task generate on linux")
}

func unload() error { return nil }

func allowV4(addr netip.Addr) error { return nil }
