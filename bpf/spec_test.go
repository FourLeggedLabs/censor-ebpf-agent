package bpf_test

import (
	"testing"

	"github.com/FourLeggedLabs/ebpf-firewall-agent/bpf"
)

func TestEmbeddedSpecParses(t *testing.T) {
	spec, err := bpf.LoadCensor()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := spec.Programs["censor_egress"]; !ok {
		t.Fatalf("programs=%v", spec.Programs)
	}
	if _, ok := spec.Maps["allow_v4"]; !ok {
		t.Fatalf("maps=%v", spec.Maps)
	}
}
