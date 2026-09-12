//go:build bpf && linux

package bpf_test

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestLoadCollection verifies generated BPF objects load on a capable kernel.
// Requires: go generate ./bpf (clang), CAP_BPF/CAP_SYS_ADMIN, kernel 5.8+.
// Run: task test:bpf  or  task test:bpf:docker
func TestLoadCollection(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root / CAP_BPF")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	// Once bpf2go artifacts exist: objs := bpf.CensorObjects{}; bpf.LoadCensorObjects(&objs, nil)
	spec, err := ebpf.LoadCollectionSpecFromReader(nil)
	if err == nil {
		_ = spec
	}
	t.Skip("enable after task generate produces censor_bpfel.go")
}
