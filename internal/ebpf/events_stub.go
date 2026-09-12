//go:build !linux

package ebpfutil

const (
	EventKindNet  = 0
	EventKindSudo = 1
)

// RawEvent mirrors the Linux ringbuf event for shared agent code.
type RawEvent struct {
	PID     uint32
	DstV4   uint32
	DstV6   [4]uint32
	Dport   uint16
	Proto   uint8
	Allowed uint8
	Family  uint8
	Kind    uint8
	Comm    [16]byte
}

func Events() <-chan RawEvent { return nil }
