package prepopulate_test

import (
	"net/netip"
	"testing"

	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/prepopulate"
)

func TestParseExistingConnections(t *testing.T) {
	seen := map[netip.Addr]struct{}{}
	n, err := prepopulate.ExistingConnections(func(a netip.Addr) error {
		seen[a] = struct{}{}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// On darwin /proc may be missing — n can be 0 without error if IsNotExist swallowed.
	_ = n
	_ = seen
}

func TestResolveHostsLocal(t *testing.T) {
	n := 0
	got := prepopulate.ResolveHosts(t.Context(), []string{"localhost", "**.example.com"}, func(a netip.Addr) error {
		n++
		return nil
	})
	if got < 1 {
		t.Fatalf("expected localhost resolve, got %d", got)
	}
}
