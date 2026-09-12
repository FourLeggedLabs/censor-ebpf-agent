//go:build bpf && linux

package bpf_test

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/FourLeggedLabs/censor-ebpf-agent/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	tcActOK   = 0
	tcActShot = 2
)

func TestEgressTestRunAllowDeny(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root / CAP_BPF")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	var objs bpf.CensorObjects
	if err := bpf.LoadCensorObjects(&objs, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	skb := craftIPv4TCP("1.2.3.4", 443)

	// Enforce + empty allow → SHOT
	zero := uint32(0)
	if err := objs.Config.Put(zero, uint32(0)); err != nil {
		t.Fatal(err)
	}
	ret, err := runEgress(objs.CensorEgress, skb)
	if err != nil {
		t.Skipf("TestRun unsupported: %v", err)
	}
	if ret != tcActShot {
		t.Fatalf("enforce empty allow: got %d want SHOT", ret)
	}

	// Insert allow /32 for 1.2.3.4 → OK
	key := bpf.CensorLpmV4Key{Prefixlen: 32, Addr: 0x01020304}
	val := uint8(1)
	if err := objs.AllowV4.Put(key, val); err != nil {
		t.Fatal(err)
	}
	ret, err = runEgress(objs.CensorEgress, skb)
	if err != nil {
		t.Fatal(err)
	}
	if ret != tcActOK {
		t.Fatalf("allowed: got %d want OK", ret)
	}

	// Monitor mode + remove allow still OK
	_ = objs.AllowV4.Delete(key)
	if err := objs.Config.Put(zero, uint32(1)); err != nil {
		t.Fatal(err)
	}
	ret, err = runEgress(objs.CensorEgress, skb)
	if err != nil {
		t.Fatal(err)
	}
	if ret != tcActOK {
		t.Fatalf("monitor: got %d want OK", ret)
	}
}

func runEgress(prog *ebpf.Program, data []byte) (uint32, error) {
	opts := &ebpf.RunOptions{Data: append([]byte(nil), data...)}
	ret, err := prog.Run(opts)
	return ret, err
}

func craftIPv4TCP(dst string, dport uint16) []byte {
	// eth(14) + ip(20) + tcp(20)
	b := make([]byte, 54)
	// ethertype IPv4
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	ip := b[14:]
	ip[0] = 0x45 // v4, ihl=5
	ip[9] = 6    // TCP
	copy(ip[16:20], []byte{1, 2, 3, 4})
	tcp := b[34:]
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	_ = dst
	return b
}
