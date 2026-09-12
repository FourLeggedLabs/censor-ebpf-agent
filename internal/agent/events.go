package agent

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	ebpfutil "github.com/FourLeggedLabs/ebpf-firewall-agent/internal/ebpf"
	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/events"
	agentv1 "github.com/FourLeggedLabs/protos/gen/go/censor/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func consumeBPFEvents(log *events.Logger, mode agentv1.Mode, ch <-chan ebpfutil.RawEvent) {
	for ev := range ch {
		action := agentv1.Action_ACTION_ALLOW
		if ev.Allowed == 0 {
			if mode == agentv1.Mode_MODE_MONITOR {
				action = agentv1.Action_ACTION_MONITOR_DENY
			} else {
				action = agentv1.Action_ACTION_DENY
			}
		}
		proto := agentv1.Protocol_PROTOCOL_UNSPECIFIED
		switch ev.Proto {
		case 6:
			proto = agentv1.Protocol_PROTOCOL_TCP
		case 17:
			proto = agentv1.Protocol_PROTOCOL_UDP
		}
		dst := ""
		if ev.Family == 6 {
			var b [16]byte
			for i := 0; i < 4; i++ {
				binary.BigEndian.PutUint32(b[i*4:], ev.DstV6[i])
			}
			dst = net.IP(b[:]).String()
		} else {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], ev.DstV4)
			dst = net.IP(b[:]).String()
		}
		_ = log.WriteEvent(&agentv1.AgentEvent{
			Ts:      timestamppb.Now(),
			Type:    agentv1.EventType_EVENT_TYPE_CONNECT,
			Action:  action,
			Pid:     ev.PID,
			Comm:    readComm(ev.PID),
			Dst:     dst,
			DstPort: uint32(ev.Dport),
			Proto:   proto,
		})
	}
}

func readComm(pid uint32) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\x00') {
		b = b[:len(b)-1]
	}
	return string(b)
}
