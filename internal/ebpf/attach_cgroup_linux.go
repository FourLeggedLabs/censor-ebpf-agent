//go:build linux

package ebpfutil

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func attachConnect4(prog *ebpf.Program) (link.Link, error) {
	return link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: prog,
	})
}

func attachConnect6(prog *ebpf.Program) (link.Link, error) {
	return link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInet6Connect,
		Program: prog,
	})
}

type egressAttach struct {
	tcx    link.Link
	filter *netlink.BpfFilter
}

func (e *egressAttach) Close() error {
	var first error
	if e.tcx != nil {
		if err := e.tcx.Close(); err != nil && first == nil {
			first = err
		}
	}
	if e.filter != nil {
		if err := netlink.FilterDel(e.filter); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// attachEgress tries TCX first, then classic clsact qdisc + bpf filter.
func attachEgress(ifaceIndex int, prog *ebpf.Program) (*egressAttach, error) {
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifaceIndex,
		Program:   prog,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err == nil {
		return &egressAttach{tcx: l}, nil
	}
	tcxErr := err
	filter, err := attachClsactFilter(ifaceIndex, prog)
	if err != nil {
		return nil, fmt.Errorf("tcx: %v; clsact: %w", tcxErr, err)
	}
	return &egressAttach{filter: filter}, nil
}

func attachClsactFilter(ifindex int, prog *ebpf.Program) (*netlink.BpfFilter, error) {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		_ = netlink.QdiscReplace(qdisc)
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           prog.FD(),
		Name:         "censor_egress",
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return nil, err
	}
	return filter, nil
}
