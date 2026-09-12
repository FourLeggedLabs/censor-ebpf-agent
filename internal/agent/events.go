package agent

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/FourLeggedLabs/censor-ebpf-agent/internal/dedupe"
	ebpfutil "github.com/FourLeggedLabs/censor-ebpf-agent/internal/ebpf"
	"github.com/FourLeggedLabs/censor-ebpf-agent/internal/events"
	agentv1 "github.com/FourLeggedLabs/protos/gen/go/censor/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func consumeBPFEvents(log *events.Logger, mode agentv1.Mode, ch <-chan ebpfutil.RawEvent) {
	cache := dedupe.New(5 * time.Second)
	for ev := range ch {
		if ev.Kind == ebpfutil.EventKindSudo {
			comm := cString(ev.Comm[:])
			_ = log.WriteEvent(&agentv1.AgentEvent{
				Ts:     timestamppb.Now(),
				Type:   agentv1.EventType_EVENT_TYPE_SUDO,
				Action: agentv1.Action_ACTION_ALLOW,
				Pid:    ev.PID,
				Comm:   comm,
				Rule:   "sudo_exec",
			})
			continue
		}

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
		dst := formatDst(ev)
		comm := readComm(ev.PID)
		if !cache.ShouldEmit(dedupe.Key{
			PID:     ev.PID,
			Dst:     dst,
			Dport:   ev.Dport,
			Proto:   ev.Proto,
			Allowed: ev.Allowed,
			Kind:    ev.Kind,
		}) {
			continue
		}
		_ = log.WriteEvent(&agentv1.AgentEvent{
			Ts:      timestamppb.Now(),
			Type:    agentv1.EventType_EVENT_TYPE_CONNECT,
			Action:  action,
			Pid:     ev.PID,
			Comm:    comm,
			Dst:     dst,
			DstPort: uint32(ev.Dport),
			Proto:   proto,
		})
	}
}

func formatDst(ev ebpfutil.RawEvent) string {
	if ev.Family == 6 {
		var b [16]byte
		for i := 0; i < 4; i++ {
			binary.BigEndian.PutUint32(b[i*4:], ev.DstV6[i])
		}
		return net.IP(b[:]).String()
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], ev.DstV4)
	return net.IP(b[:]).String()
}

func cString(b []byte) string {
	s := string(b)
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	return s
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
