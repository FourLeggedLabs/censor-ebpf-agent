module github.com/FourLeggedLabs/ebpf-firewall-agent

go 1.27.0

replace github.com/FourLeggedLabs/protos/gen/go => /Users/behn/Developer/protos/gen/go

require (
	github.com/FourLeggedLabs/protos/gen/go v0.0.0-00010101000000-000000000000
	google.golang.org/protobuf v1.36.12
)
