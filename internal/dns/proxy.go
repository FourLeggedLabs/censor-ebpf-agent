package dns

import (
	"fmt"
	"net"
	"strings"

	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/policy"
	agentv1 "github.com/FourLeggedLabs/protos/gen/go/censor/agent/v1"
	"github.com/miekg/dns"
)

// EventFunc is called for DNS decisions (may be nil).
type EventFunc func(host string, action agentv1.Action, rule string)

// AllowIPFunc is called when an allowed name resolves (JIT allowlist).
type AllowIPFunc func(ip net.IP)

// Proxy is a local DNS forwarder that filters by policy.
type Proxy struct {
	Upstream string // host:port
	Mode     agentv1.Mode
	Allowed  []string
	Denied   []string
	OnEvent  EventFunc
	OnAllow  AllowIPFunc

	server *dns.Server
}

// Start listens on addr (e.g. 127.0.0.1:53) and serves until Shutdown.
func (p *Proxy) Start(addr string) error {
	p.server = &dns.Server{Addr: addr, Net: "udp", Handler: p}
	go func() { _ = p.server.ListenAndServe() }()
	tcp := &dns.Server{Addr: addr, Net: "tcp", Handler: p}
	go func() { _ = tcp.ListenAndServe() }()
	return nil
}

// ServeDNS implements dns.Handler.
func (p *Proxy) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	p.handle(w, r)
}

// Shutdown stops the UDP server.
func (p *Proxy) Shutdown() error {
	if p.server == nil {
		return nil
	}
	return p.server.Shutdown()
}

func (p *Proxy) handle(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		_ = w.WriteMsg(new(dns.Msg))
		return
	}
	q := r.Question[0]
	host := strings.TrimSuffix(q.Name, ".")
	dec := policy.EvaluateHost(p.Allowed, p.Denied, host)

	if !dec.Allow {
		action := agentv1.Action_ACTION_DENY
		if p.Mode == agentv1.Mode_MODE_MONITOR {
			action = agentv1.Action_ACTION_MONITOR_DENY
		} else {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeNameError)
			_ = w.WriteMsg(m)
			if p.OnEvent != nil {
				p.OnEvent(host, action, dec.Rule)
			}
			return
		}
		if p.OnEvent != nil {
			p.OnEvent(host, action, dec.Rule)
		}
	} else if p.OnEvent != nil {
		p.OnEvent(host, agentv1.Action_ACTION_ALLOW, dec.Rule)
	}

	c := &dns.Client{Net: "udp"}
	in, _, err := c.Exchange(r, p.Upstream)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	if dec.Allow || p.Mode == agentv1.Mode_MODE_MONITOR {
		for _, rr := range in.Answer {
			switch v := rr.(type) {
			case *dns.A:
				if p.OnAllow != nil {
					p.OnAllow(v.A)
				}
			case *dns.AAAA:
				if p.OnAllow != nil {
					p.OnAllow(v.AAAA)
				}
			}
		}
	}
	_ = w.WriteMsg(in)
}

// ListenPacket is a test helper that binds an ephemeral UDP port.
func ListenPacket() (addr string, cleanup func(), err error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	a := pc.LocalAddr().(*net.UDPAddr)
	_ = pc.Close()
	return fmt.Sprintf("127.0.0.1:%d", a.Port), func() {}, nil
}
