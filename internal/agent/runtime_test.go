package agent_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/agent"
	"github.com/miekg/dns"
)

func TestStartWaitReadyWithLocalConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "policy.json")
	policy := `{
	  "correlationId": "t1",
	  "mode": "MODE_MONITOR",
	  "allowedHosts": ["github.com"],
	  "watchSudo": true
	}`
	if err := os.WriteFile(cfgPath, []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}

	upPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upMux := dns.NewServeMux()
	upMux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
	})
	upSrv := &dns.Server{PacketConn: upPC, Handler: upMux}
	go func() { _ = upSrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = upSrv.Shutdown() })

	dnsPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dnsAddr := dnsPC.LocalAddr().String()
	_ = dnsPC.Close()

	ready := filepath.Join(dir, "ready")
	fail := filepath.Join(dir, "fail")
	pid := filepath.Join(dir, "pid")
	logPath := filepath.Join(dir, "agent.ndjson")

	ctx := context.Background()
	rt, err := agent.Start(ctx, agent.Config{
		ConfigFile:  cfgPath,
		LogPath:     logPath,
		ReadyFile:   ready,
		FailureFile: fail,
		PidFile:     pid,
		DNSListen:   dnsAddr,
		DNSUpstream: upPC.LocalAddr().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rt.Close() })

	if err := agent.WaitReady(ready, fail, 2*time.Second); err != nil {
		t.Fatal(err)
	}
}
