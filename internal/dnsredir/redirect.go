package dnsredir

import (
	"fmt"
	"os/exec"
	"strings"
)

// Redirect installs OUTPUT DNAT so UDP/TCP :53 (except loopback) goes to listenAddr.
// Uses iptables-nft or iptables; records rules for Remove.
type Redirect struct {
	ListenHost string // e.g. 127.0.0.1
	ListenPort string // e.g. 53
	backend    string // iptables or iptables-nft
	installed  bool
}

// Enable adds DNAT + INPUT drop of unsolicited DNS from non-lo (best-effort).
func (r *Redirect) Enable() error {
	if r.ListenHost == "" {
		r.ListenHost = "127.0.0.1"
	}
	if r.ListenPort == "" {
		r.ListenPort = "53"
	}
	backend, err := pickIptables()
	if err != nil {
		return err
	}
	r.backend = backend
	dest := r.ListenHost + ":" + r.ListenPort
	rules := [][]string{
		{"-t", "nat", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "!", "-d", "127.0.0.0/8", "-j", "DNAT", "--to-destination", dest},
		{"-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "!", "-d", "127.0.0.0/8", "-j", "DNAT", "--to-destination", dest},
	}
	for _, args := range rules {
		if out, err := exec.Command(backend, args...).CombinedOutput(); err != nil {
			_ = r.Remove()
			return fmt.Errorf("%s %s: %w (%s)", backend, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}
	// Flush DNS conntrack so existing flows pick up DNAT (best-effort).
	_ = exec.Command("conntrack", "-D", "-p", "udp", "--dport", "53").Run()
	_ = exec.Command("conntrack", "-D", "-p", "tcp", "--dport", "53").Run()
	r.installed = true
	return nil
}

// Remove deletes the DNAT rules if Enable succeeded.
func (r *Redirect) Remove() error {
	if r.backend == "" {
		return nil
	}
	dest := r.ListenHost + ":" + r.ListenPort
	rules := [][]string{
		{"-t", "nat", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "!", "-d", "127.0.0.0/8", "-j", "DNAT", "--to-destination", dest},
		{"-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "!", "-d", "127.0.0.0/8", "-j", "DNAT", "--to-destination", dest},
	}
	var first error
	for _, args := range rules {
		if out, err := exec.Command(r.backend, args...).CombinedOutput(); err != nil && first == nil {
			// Rule may already be gone.
			if !strings.Contains(string(out), "No chain") && !strings.Contains(string(out), "Bad rule") {
				first = fmt.Errorf("%s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
			}
		}
	}
	r.installed = false
	return first
}

func pickIptables() (string, error) {
	for _, c := range []string{"iptables-nft", "iptables"} {
		if path, err := exec.LookPath(c); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("iptables not found")
}

// DockerBridgeDNS rewrites /etc/docker/daemon.json dns to point at bridgeDNS (e.g. docker0 IP).
// Kept minimal: only sets "dns" key; restores backup on Disable.
type DockerDNS struct {
	DaemonJSON string
	DNS        []string
	backup     []byte
	hadFile    bool
	enabled    bool
}

// DefaultDockerDaemonJSON is the usual path on GHA Ubuntu runners.
const DefaultDockerDaemonJSON = "/etc/docker/daemon.json"
