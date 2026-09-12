package bpf

// Package bpf holds generated eBPF objects (see generate.go).
//
// Test strategy:
//   - Unit tests without kernel: map key helpers in internal/ebpf (pure Go).
//   - Integration: //go:build bpf && linux — load CollectionSpec via cilium/ebpf
//     and optionally Program.TestRun with a synthetic IPv4 skb.
//   - CI: ubuntu-latest job `task test:bpf` (privileged) and
//     `task test:bpf:docker` for local Mac/dev.
