package ebpfutil

import (
	"encoding/binary"
	"net/netip"
)

// LPMKeyV4 is the userspace view of the BPF LPM trie key (prefixlen + IPv4 BE).
type LPMKeyV4 struct {
	PrefixLen uint32
	Addr      uint32 // big-endian IPv4 as u32
}

// NewLPMKeyV4 builds a /32 allow key for addr.
func NewLPMKeyV4(addr netip.Addr) (LPMKeyV4, error) {
	if !addr.Is4() {
		return LPMKeyV4{}, errNotV4
	}
	b := addr.As4()
	return LPMKeyV4{
		PrefixLen: 32,
		Addr:      binary.BigEndian.Uint32(b[:]),
	}, nil
}

type notV4Error struct{}

func (notV4Error) Error() string { return "address is not IPv4" }

var errNotV4 = notV4Error{}

// Config indices in the BPF config array.
const (
	ConfigAuditMode = 0 // 1=monitor, 0=enforce
	ConfigEnabled   = 1
)
