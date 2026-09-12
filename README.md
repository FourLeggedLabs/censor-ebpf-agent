# Censor eBPF Firewall Agent

Linux amd64/arm64 agent that enforces egress policy on GitHub Actions runners via eBPF.

## GitHub Actions

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: FourLeggedLabs/censor-ebpf-agent@v0.1.0
        with:
          api-url: ${{ vars.CENSOR_API_URL }}
          api-key: ${{ secrets.CENSOR_API_KEY }}

      # … your job steps …

      - if: always()
        uses: FourLeggedLabs/censor-ebpf-agent/stop@v0.1.0
```

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
