package agent

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/api"
	censordns "github.com/FourLeggedLabs/ebpf-firewall-agent/internal/dns"
	ebpfutil "github.com/FourLeggedLabs/ebpf-firewall-agent/internal/ebpf"
	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/events"
	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/gha"
	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/sudo"
	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/version"
	agentv1 "github.com/FourLeggedLabs/protos/gen/go/censor/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	DefaultReadyFile   = "/var/run/censor/ready"
	DefaultFailureFile = "/var/run/censor/failure"
	DefaultPidFile     = "/var/run/censor/censor.pid"
	DefaultAPIKeyPath  = "/etc/censor/api-key"
)

// Config is runtime configuration for Start.
type Config struct {
	APIURL       string
	APIKeyPath   string
	ConfigFile   string // optional protojson AgentPolicy bypass
	LogPath      string
	ReadyFile    string
	FailureFile  string
	PidFile      string
	DNSListen    string
	DNSUpstream  string
	GitHubActions bool
	Status       string // for upload on stop
}

// Runtime is a started agent.
type Runtime struct {
	cfg    Config
	policy *agentv1.AgentPolicy
	ghac   *gha.Context
	log    *events.Logger
	dns    *censordns.Proxy
	lock   *sudo.Lockdown
	client *api.Client
}

// Start loads policy, opens log, starts DNS proxy, writes ready sentinel.
// BPF attach is best-effort via AttachFirewall (no-op/stub on unsupported platforms).
func Start(ctx context.Context, cfg Config) (*Runtime, error) {
	cfg = defaults(cfg)
	if err := os.MkdirAll(filepath.Dir(cfg.ReadyFile), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(cfg.ReadyFile)
	_ = os.Remove(cfg.FailureFile)

	ghac, err := gha.FromEnv()
	if err != nil {
		return nil, writeFail(cfg.FailureFile, err)
	}

	client := &api.Client{BaseURL: cfg.APIURL, Version: version.String()}
	if cfg.ConfigFile == "" {
		key, err := api.LoadAPIKey(cfg.APIKeyPath)
		if err != nil {
			return nil, writeFail(cfg.FailureFile, err)
		}
		client.APIKey = key
	}

	var pol *agentv1.AgentPolicy
	if cfg.ConfigFile != "" {
		b, err := os.ReadFile(cfg.ConfigFile)
		if err != nil {
			return nil, writeFail(cfg.FailureFile, err)
		}
		pol = &agentv1.AgentPolicy{}
		if err := protoJSONUnmarshal(b, pol); err != nil {
			return nil, writeFail(cfg.FailureFile, err)
		}
	} else {
		if cfg.APIURL == "" {
			return nil, writeFail(cfg.FailureFile, fmt.Errorf("CENSOR_API_URL required"))
		}
		pol, err = client.FetchPolicy(ctx, ghac)
		if err != nil {
			return nil, writeFail(cfg.FailureFile, err)
		}
	}

	log, err := events.Open(cfg.LogPath)
	if err != nil {
		return nil, writeFail(cfg.FailureFile, err)
	}

	rt := &Runtime{cfg: cfg, policy: pol, ghac: ghac, log: log, client: client}

	if pol.GetDisableSudo() {
		rt.lock = &sudo.Lockdown{}
		if err := rt.lock.Enable(); err != nil {
			_ = log.Close()
			return nil, writeFail(cfg.FailureFile, err)
		}
	}

	allowIPs := func(ip net.IP) {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return
		}
		_ = ebpfutil.AllowIP(addr) // no-op stub until maps wired
	}

	rt.dns = &censordns.Proxy{
		Upstream: cfg.DNSUpstream,
		Mode:     pol.GetMode(),
		Allowed:  pol.GetAllowedHosts(),
		Denied:   pol.GetDeniedHosts(),
		OnAllow:  allowIPs,
		OnEvent: func(host string, action agentv1.Action, rule string) {
			_ = log.WriteEvent(&agentv1.AgentEvent{
				Ts:     timestamppb.Now(),
				Type:   agentv1.EventType_EVENT_TYPE_DNS,
				Action: action,
				Host:   host,
				Rule:   rule,
			})
		},
	}
	if err := rt.dns.Start(cfg.DNSListen); err != nil {
		_ = rt.Close()
		return nil, writeFail(cfg.FailureFile, err)
	}

	if err := ebpfutil.AttachFirewall(pol.GetMode() == agentv1.Mode_MODE_MONITOR); err != nil {
		// Soft-fail on Darwin / missing caps so unit lifecycle can still be tested with DNS.
		_ = log.WriteEvent(&agentv1.AgentEvent{
			Ts:     timestamppb.Now(),
			Type:   agentv1.EventType_EVENT_TYPE_CONNECT,
			Action: agentv1.Action_ACTION_ALLOW,
			Rule:   "bpf_attach_skipped:" + err.Error(),
		})
	}

	if err := os.WriteFile(cfg.PidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
		_ = rt.Close()
		return nil, writeFail(cfg.FailureFile, err)
	}
	if err := os.WriteFile(cfg.ReadyFile, []byte("ok\n"), 0o644); err != nil {
		_ = rt.Close()
		return nil, writeFail(cfg.FailureFile, err)
	}
	return rt, nil
}

// Close tears down DNS/log/sudo (BPF detach via ebpfutil).
func (rt *Runtime) Close() error {
	var first error
	if rt.dns != nil {
		if err := rt.dns.Shutdown(); err != nil && first == nil {
			first = err
		}
	}
	_ = ebpfutil.DetachFirewall()
	if rt.lock != nil {
		_ = rt.lock.Disable()
	}
	if rt.log != nil {
		if err := rt.log.Close(); err != nil && first == nil {
			first = err
		}
	}
	_ = os.Remove(rt.cfg.ReadyFile)
	_ = os.Remove(rt.cfg.PidFile)
	return first
}

// Upload gzips the log and POSTs to the API.
func (rt *Runtime) Upload(ctx context.Context, status string) error {
	if rt.cfg.ConfigFile != "" && rt.cfg.APIURL == "" {
		return nil
	}
	raw, err := rt.log.ReadFile()
	if err != nil {
		return err
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write(raw); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	jc, err := rt.ghac.Proto()
	if err != nil {
		return err
	}
	meta := &agentv1.AgentLogUpload{
		CorrelationId: rt.policy.GetCorrelationId(),
		Job:           jc,
		Mode:          rt.policy.GetMode(),
		AgentVersion:  version.String(),
		Status:        status,
	}
	return rt.client.UploadLogs(ctx, meta, gz.Bytes())
}

func defaults(cfg Config) Config {
	if cfg.APIKeyPath == "" {
		cfg.APIKeyPath = DefaultAPIKeyPath
	}
	if cfg.LogPath == "" {
		cfg.LogPath = events.DefaultLogPath
	}
	if cfg.ReadyFile == "" {
		cfg.ReadyFile = DefaultReadyFile
	}
	if cfg.FailureFile == "" {
		cfg.FailureFile = DefaultFailureFile
	}
	if cfg.PidFile == "" {
		cfg.PidFile = DefaultPidFile
	}
	if cfg.DNSListen == "" {
		cfg.DNSListen = "127.0.0.1:53"
	}
	if cfg.DNSUpstream == "" {
		cfg.DNSUpstream = "8.8.8.8:53"
	}
	if cfg.Status == "" {
		cfg.Status = "success"
	}
	if v := os.Getenv("CENSOR_API_URL"); cfg.APIURL == "" {
		cfg.APIURL = v
	}
	if v := os.Getenv("CENSOR_CONFIG_FILE"); cfg.ConfigFile == "" {
		cfg.ConfigFile = v
	}
	return cfg
}

func writeFail(path string, err error) error {
	if path != "" {
		_ = os.MkdirAll(filepath.Dir(path), 0o755)
		_ = os.WriteFile(path, []byte(err.Error()+"\n"), 0o644)
	}
	return err
}

// WaitReady polls ready/failure files.
func WaitReady(ready, failure string, timeout time.Duration) error {
	if ready == "" {
		ready = DefaultReadyFile
	}
	if failure == "" {
		failure = DefaultFailureFile
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(failure); err == nil && len(b) > 0 {
			return fmt.Errorf("censor failed: %s", bytes.TrimSpace(b))
		}
		if _, err := os.Stat(ready); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for %s", ready)
}
