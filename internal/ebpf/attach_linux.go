//go:build linux

package ebpfutil

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/FourLeggedLabs/ebpf-firewall-agent/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// RawEvent is the ringbuf payload from censor.c.
type RawEvent struct {
	PID     uint32
	Dst     uint32 // big-endian IPv4
	Dport   uint16
	Proto   uint8
	Allowed uint8
}

var (
	mu       sync.Mutex
	objs     bpf.CensorObjects
	cgLink   link.Link
	tcLink   link.Link
	rd       *ringbuf.Reader
	loaded   bool
	eventCh  chan RawEvent
)

// AttachFirewall loads programs, attaches cgroup connect4 + TCX egress, starts ringbuf reader.
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

	iface, err := egressInterface()
	if err != nil {
		_ = cgLink.Close()
		_ = objs.Close()
		return fmt.Errorf("iface: %w", err)
	}
	tcLink, err = link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.CensorEgress,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		_ = cgLink.Close()
		_ = objs.Close()
		return fmt.Errorf("attach tcx: %w", err)
	}

	rd, err = ringbuf.NewReader(objs.Events)
	if err != nil {
		_ = tcLink.Close()
		_ = cgLink.Close()
		_ = objs.Close()
		return fmt.Errorf("ringbuf: %w", err)
	}
	eventCh = make(chan RawEvent, 1024)
	go readEvents(rd, eventCh)

	loaded = true
	return nil
}

// Events returns the live event channel (nil if not attached).
func Events() <-chan RawEvent {
	mu.Lock()
	defer mu.Unlock()
	return eventCh
}

func readEvents(r *ringbuf.Reader, ch chan RawEvent) {
	for {
		rec, err := r.Read()
		if err != nil {
			return
		}
		if len(rec.RawSample) < 12 {
			continue
		}
		ev := RawEvent{
			PID:     binary.LittleEndian.Uint32(rec.RawSample[0:4]),
			Dst:     binary.LittleEndian.Uint32(rec.RawSample[4:8]),
			Dport:   binary.LittleEndian.Uint16(rec.RawSample[8:10]),
			Proto:   rec.RawSample[10],
			Allowed: rec.RawSample[11],
		}
		select {
		case ch <- ev:
		default:
		}
	}
}

func DetachFirewall() error {
	mu.Lock()
	defer mu.Unlock()
	if !loaded {
		return nil
	}
	if rd != nil {
		_ = rd.Close()
		rd = nil
	}
	if tcLink != nil {
		_ = tcLink.Close()
		tcLink = nil
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

func egressInterface() (*net.Interface, error) {
	if name := os.Getenv("CENSOR_INTERFACE"); name != "" {
		return net.InterfaceByName(name)
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifs {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		return &iface, nil
	}
	return nil, fmt.Errorf("no suitable egress interface")
}
