package ebpfutil_test

import (
	"net/netip"
	"testing"

	ebpfutil "github.com/FourLeggedLabs/ebpf-firewall-agent/internal/ebpf"
)

func TestNewLPMKeyV4(t *testing.T) {
	k, err := ebpfutil.NewLPMKeyV4(netip.MustParseAddr("1.2.3.4"))
	if err != nil {
		t.Fatal(err)
	}
	if k.PrefixLen != 32 {
		t.Fatal(k.PrefixLen)
	}
	// 1.2.3.4 in BE = 0x01020304
	if k.Addr != 0x01020304 {
		t.Fatalf("%#x", k.Addr)
	}
	if _, err := ebpfutil.NewLPMKeyV4(netip.MustParseAddr("::1")); err == nil {
		t.Fatal("expected error")
	}
}
