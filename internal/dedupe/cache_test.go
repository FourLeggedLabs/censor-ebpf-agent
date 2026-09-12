package dedupe_test

import (
	"testing"
	"time"

	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/dedupe"
)

func TestCacheSuppressesDuplicates(t *testing.T) {
	c := dedupe.New(time.Hour)
	k := dedupe.Key{PID: 1, Dst: "1.2.3.4", Dport: 443, Proto: 6}
	if !c.ShouldEmit(k) {
		t.Fatal("first should emit")
	}
	if c.ShouldEmit(k) {
		t.Fatal("second should suppress")
	}
	k2 := k
	k2.Dport = 80
	if !c.ShouldEmit(k2) {
		t.Fatal("different key should emit")
	}
}

func TestCacheTTLExpiry(t *testing.T) {
	c := dedupe.New(10 * time.Millisecond)
	k := dedupe.Key{PID: 2, Dst: "9.9.9.9", Dport: 53, Proto: 17}
	if !c.ShouldEmit(k) {
		t.Fatal("first")
	}
	time.Sleep(25 * time.Millisecond)
	if !c.ShouldEmit(k) {
		t.Fatal("after ttl should emit again")
	}
}
