//go:build bpf && linux

package bpf_test

import (
	"os"
	"testing"

	"github.com/FourLeggedLabs/censor-ebpf-agent/bpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestLoadCensorObjects(t *testing.T) {
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
	if objs.CensorEgress == nil || objs.AllowV4 == nil {
		t.Fatal("missing programs/maps")
	}
}

func TestLoadCollectionSpec(t *testing.T) {
	spec, err := bpf.LoadCensor()
	if err != nil {
		t.Fatal(err)
	}
	if spec.Programs["censor_egress"] == nil {
		t.Fatal("missing censor_egress")
	}
}
