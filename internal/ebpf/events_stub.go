//go:build !linux

package ebpfutil

// RawEvent mirrors the Linux ringbuf event for shared agent code.
type RawEvent struct {
	PID     uint32
	Dst     uint32
	Dport   uint16
	Proto   uint8
	Allowed uint8
}

// Events is nil on non-Linux.
func Events() <-chan RawEvent { return nil }
