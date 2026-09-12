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
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// RawEvent is the ringbuf payload from censor.c (keep in sync with struct event).
type RawEvent struct {
	PID     uint32
	DstV4   uint32
	DstV6   [4]uint32
	Dport   uint16
	Proto   uint8
	Allowed uint8
	Family  uint8
}

var (
	mu      sync.Mutex
	objs    bpf.CensorObjects
	cg4     link.Link
	cg6     link.Link
	tcAtt   *egressAttach
	rd      *ringbuf.Reader
	loaded  bool
	eventCh chan RawEvent
)

// AttachFirewall loads programs, attaches cgroup connect4/6 + TC egress, starts ringbuf reader.
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
	cg4, err = attachConnect4(objs.CensorConnect4)
	if err != nil {
		_ = objs.Close()
		return fmt.Errorf("attach connect4: %w", err)
	}
	cg6, err = attachConnect6(objs.CensorConnect6)
	if err != nil {
		_ = cg4.Close()
		_ = objs.Close()
		return fmt.Errorf("attach connect6: %w", err)
	}

	iface, err := egressInterface()
	if err != nil {
		_ = cg6.Close()
		_ = cg4.Close()
		_ = objs.Close()
		return fmt.Errorf("iface: %w", err)
	}
	tcAtt, err = attachEgress(iface.Index, objs.CensorEgress)
	if err != nil {
		_ = cg6.Close()
		_ = cg4.Close()
		_ = objs.Close()
		return fmt.Errorf("attach egress: %w", err)
	}

	rd, err = ringbuf.NewReader(objs.Events)
	if err != nil {
		_ = tcAtt.Close()
		_ = cg6.Close()
		_ = cg4.Close()
		_ = objs.Close()
		return fmt.Errorf("ringbuf: %w", err)
	}
	eventCh = make(chan RawEvent, 1024)
	go readEvents(rd, eventCh)

	loaded = true
	return nil
}

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
		// pid(4)+dst4(4)+dst6(16)+dport(2)+proto(1)+allowed(1)+family(1)+pad(3) = 32
		if len(rec.RawSample) < 32 {
			continue
		}
		ev := RawEvent{
			PID:     binary.LittleEndian.Uint32(rec.RawSample[0:4]),
			DstV4:   binary.LittleEndian.Uint32(rec.RawSample[4:8]),
			Dport:   binary.LittleEndian.Uint16(rec.RawSample[24:26]),
			Proto:   rec.RawSample[26],
			Allowed: rec.RawSample[27],
			Family:  rec.RawSample[28],
		}
		for i := 0; i < 4; i++ {
			ev.DstV6[i] = binary.LittleEndian.Uint32(rec.RawSample[8+i*4 : 12+i*4])
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
	if tcAtt != nil {
		_ = tcAtt.Close()
		tcAtt = nil
	}
	if cg6 != nil {
		_ = cg6.Close()
		cg6 = nil
	}
	if cg4 != nil {
		_ = cg4.Close()
		cg4 = nil
	}
	_ = objs.Close()
	loaded = false
	return nil
}

func AllowIP(addr netip.Addr) error {
	mu.Lock()
	defer mu.Unlock()
	if !loaded {
		return nil
	}
	val := uint8(1)
	if addr.Is4() {
		b := addr.As4()
		key := bpf.CensorLpmV4Key{
			Prefixlen: 32,
			Addr:      binary.BigEndian.Uint32(b[:]),
		}
		return objs.AllowV4.Put(key, val)
	}
	if addr.Is6() {
		b := addr.As16()
		key := bpf.CensorLpmV6Key{Prefixlen: 128}
		for i := 0; i < 4; i++ {
			key.Addr[i] = binary.BigEndian.Uint32(b[i*4 : (i+1)*4])
		}
		return objs.AllowV6.Put(key, val)
	}
	return nil
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
