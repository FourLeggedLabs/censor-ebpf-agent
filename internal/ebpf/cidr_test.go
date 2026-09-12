package ebpfutil_test

import (
	"net/netip"
	"testing"

	ebpfutil "github.com/FourLeggedLabs/censor-ebpf-agent/internal/ebpf"
)

func TestParseAndAllowCIDRs(t *testing.T) {
	n, errs := ebpfutil.ParseAndAllowCIDRs([]string{"10.0.0.0/8", "not-a-cidr", "fd00::/8"})
	if n != 2 {
		t.Fatalf("n=%d errs=%v", n, errs)
	}
	if len(errs) != 1 {
		t.Fatalf("errs=%v", errs)
	}
	_, err := netip.ParsePrefix("10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
}
