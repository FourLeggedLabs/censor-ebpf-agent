# Censor eBPF Firewall Agent

Linux amd64/arm64 agent that enforces egress policy on GitHub Actions runners via eBPF.

## Develop

Requires [mise](https://mise.jdx.dev) (Go 1.27.1), [Task](https://taskfile.dev), and on Linux: clang/llvm for BPF generation.

```bash
task test          # unit tests
task build         # host binary
task build:linux   # amd64 + arm64
task test:bpf      # Linux + CAP_BPF (skips elsewhere)
task test:bpf:docker  # privileged container
```

Schemas: [`FourLeggedLabs/protos`](https://github.com/FourLeggedLabs/protos) (`censor.agent.v1`).

## CLI

```
censor start | wait-ready | stop | version
```
