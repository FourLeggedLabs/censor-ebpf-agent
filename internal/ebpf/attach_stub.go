//go:build !linux

package ebpfutil

import (
	"fmt"
	"net/netip"
)

// AttachFirewall is a stub on non-Linux platforms.
func AttachFirewall(auditMode, watchSudo bool) error {
	return fmt.Errorf("ebpf attach requires linux")
}

// DetachFirewall is a no-op stub.
func DetachFirewall() error { return nil }

// AllowIP is a no-op stub.
func AllowIP(addr netip.Addr) error { return nil }
