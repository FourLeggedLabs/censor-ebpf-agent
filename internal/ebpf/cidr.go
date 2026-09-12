package ebpfutil

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// AllowPrefix inserts an IPv4/IPv6 prefix into the allow LPM maps.
// No-op on non-Linux or before AttachFirewall (AllowIP handles that via loaded check).
func AllowPrefix(prefix netip.Prefix) error {
	if !prefix.IsValid() {
		return fmt.Errorf("invalid prefix")
	}
	prefix = prefix.Masked()
	addr := prefix.Addr()
	bits := prefix.Bits()
	if addr.Is4() {
		b := addr.As4()
		return allowV4Prefix(binary.BigEndian.Uint32(b[:]), uint32(bits))
	}
	if addr.Is6() {
		b := addr.As16()
		var words [4]uint32
		for i := 0; i < 4; i++ {
			words[i] = binary.BigEndian.Uint32(b[i*4 : (i+1)*4])
		}
		return allowV6Prefix(words, uint32(bits))
	}
	return fmt.Errorf("unsupported address family")
}

// ParseAndAllowCIDRs parses CIDR strings and inserts them; skips invalid entries.
func ParseAndAllowCIDRs(cidrs []string) (n int, errs []error) {
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			errs = append(errs, fmt.Errorf("%q: %w", s, err))
			continue
		}
		if err := AllowPrefix(p); err != nil {
			errs = append(errs, fmt.Errorf("%q: %w", s, err))
			continue
		}
		n++
	}
	return n, errs
}
