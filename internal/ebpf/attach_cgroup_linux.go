//go:build linux

package ebpfutil

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func attachConnect4(prog *ebpf.Program) (link.Link, error) {
	return link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: prog,
	})
}
