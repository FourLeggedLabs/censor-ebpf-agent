//go:build linux

package ebpfutil

import "github.com/FourLeggedLabs/censor-ebpf-agent/bpf"

func allowV4Prefix(addrBE, prefixLen uint32) error {
	mu.Lock()
	defer mu.Unlock()
	if !loaded {
		return nil
	}
	key := bpf.CensorLpmV4Key{Prefixlen: prefixLen, Addr: addrBE}
	val := uint8(1)
	return objs.AllowV4.Put(key, val)
}

func allowV6Prefix(addr [4]uint32, prefixLen uint32) error {
	mu.Lock()
	defer mu.Unlock()
	if !loaded {
		return nil
	}
	key := bpf.CensorLpmV6Key{Prefixlen: prefixLen, Addr: addr}
	val := uint8(1)
	return objs.AllowV6.Put(key, val)
}
