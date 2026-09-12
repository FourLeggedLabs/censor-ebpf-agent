//go:build !linux

package ebpfutil

func allowV4Prefix(addrBE, prefixLen uint32) error { return nil }
func allowV6Prefix(addr [4]uint32, prefixLen uint32) error {
	return nil
}
