module github.com/FourLeggedLabs/ebpf-firewall-agent

go 1.27.0

replace github.com/FourLeggedLabs/protos/gen/go => /Users/behn/Developer/protos/gen/go

require (
	github.com/FourLeggedLabs/protos/gen/go v0.0.0-00010101000000-000000000000
	github.com/cilium/ebpf v0.22.0
	github.com/miekg/dns v1.1.73
	google.golang.org/protobuf v1.36.12
)

require (
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
