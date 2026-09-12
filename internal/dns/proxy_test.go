package dns_test

import (
	"net"
	"testing"
	"time"

	censordns "github.com/FourLeggedLabs/censor-ebpf-agent/internal/dns"
	agentv1 "github.com/FourLeggedLabs/protos/gen/go/censor/agent/v1"
	"github.com/miekg/dns"
)

func TestProxyEnforceNXDOMAIN(t *testing.T) {
	upMux := dns.NewServeMux()
	upMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(9, 9, 9, 9),
		})
		_ = w.WriteMsg(m)
	})
	upPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upSrv := &dns.Server{PacketConn: upPC, Handler: upMux}
	go func() { _ = upSrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = upSrv.Shutdown() })

	proxyPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var sawDeny bool
	p := &censordns.Proxy{
		Upstream: upPC.LocalAddr().String(),
		Mode:     agentv1.Mode_MODE_ENFORCE,
		Allowed:  []string{"github.com"},
		OnEvent: func(host string, action agentv1.Action, _ string) {
			if host == "evil.example" && action == agentv1.Action_ACTION_DENY {
				sawDeny = true
			}
		},
	}
	srv := &dns.Server{PacketConn: proxyPC, Handler: p}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	time.Sleep(50 * time.Millisecond)
	c := &dns.Client{Timeout: time.Second}
	m := new(dns.Msg)
	m.SetQuestion("evil.example.", dns.TypeA)
	in, _, err := c.Exchange(m, proxyPC.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if in.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode %d", in.Rcode)
	}
	if !sawDeny {
		t.Fatal("expected deny event")
	}

	m.SetQuestion("github.com.", dns.TypeA)
	in, _, err = c.Exchange(m, proxyPC.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if in.Rcode != dns.RcodeSuccess || len(in.Answer) == 0 {
		t.Fatalf("allow failed: %+v", in)
	}
}

func TestProxyMonitorForwardsDenied(t *testing.T) {
	upMux := dns.NewServeMux()
	upMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IPv4(1, 2, 3, 4),
		})
		_ = w.WriteMsg(m)
	})
	upPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upSrv := &dns.Server{PacketConn: upPC, Handler: upMux}
	go func() { _ = upSrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = upSrv.Shutdown() })

	proxyPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &censordns.Proxy{
		Upstream: upPC.LocalAddr().String(),
		Mode:     agentv1.Mode_MODE_MONITOR,
		Allowed:  nil,
	}
	srv := &dns.Server{PacketConn: proxyPC, Handler: p}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	time.Sleep(50 * time.Millisecond)

	c := &dns.Client{Timeout: time.Second}
	m := new(dns.Msg)
	m.SetQuestion("blocked.example.", dns.TypeA)
	in, _, err := c.Exchange(m, proxyPC.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if in.Rcode != dns.RcodeSuccess {
		t.Fatalf("monitor should forward, rcode=%d", in.Rcode)
	}
}
