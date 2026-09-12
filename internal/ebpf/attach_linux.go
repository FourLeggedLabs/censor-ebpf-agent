//go:build linux

package ebpfutil

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"

	"github.com/FourLeggedLabs/ebpf-firewall-agent/bpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

var (
	mu     sync.Mutex
	objs   bpf.CensorObjects
	cgLink link.Link
	loaded bool
)

// AttachFirewall loads programs into the kernel and attaches cgroup connect4.
// TC egress attach needs iface discovery (follow-up); allow map is live for JIT DNS.
func AttachFirewall(auditMode bool) error {
	mu.Lock()
	defer mu.Unlock()
	if loaded {
		return nil
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}
	if err := bpf.LoadCensorObjects(&objs, nil); err != nil {
		return fmt.Errorf("load bpf: %w", err)
	}
	audit := uint32(0)
	if auditMode {
		audit = 1
	}
	key := uint32(ConfigAuditMode)
	if err := objs.Config.Put(key, audit); err != nil {
		_ = objs.Close()
		return fmt.Errorf("config: %w", err)
	}
	var err error
	cgLink, err = attachConnect4(objs.CensorConnect4)
	if err != nil {
		_ = objs.Close()
		return fmt.Errorf("attach connect4: %w", err)
	}
	loaded = true
	return nil
}

func DetachFirewall() error {
	mu.Lock()
	defer mu.Unlock()
	if !loaded {
		return nil
	}
	if cgLink != nil {
		_ = cgLink.Close()
		cgLink = nil
	}
	_ = objs.Close()
	loaded = false
	return nil
}

func AllowIP(addr netip.Addr) error {
	mu.Lock()
	defer mu.Unlock()
	if !loaded || !addr.Is4() {
		return nil
	}
	b := addr.As4()
	key := bpf.CensorLpmV4Key{
		Prefixlen: 32,
		Addr:      binary.BigEndian.Uint32(b[:]),
	}
	val := uint8(1)
	return objs.AllowV4.Put(key, val)
}
