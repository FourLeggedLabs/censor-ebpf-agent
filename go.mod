module github.com/FourLeggedLabs/censor-ebpf-agent

go 1.27.0

require (
	github.com/FourLeggedLabs/protos/gen/go v0.1.0
	github.com/cilium/ebpf v0.22.0
	github.com/miekg/dns v1.1.73
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sys v0.47.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/net v0.57.0 // indirect
)
