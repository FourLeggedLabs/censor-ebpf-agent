package dnsredir_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/dnsredir"
)

func TestDockerDNSRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.json")
	orig := []byte(`{"log-driver":"json-file"}` + "\n")
	if err := os.WriteFile(path, orig, 0o644); err != nil {
		t.Fatal(err)
	}
	d := &dnsredir.DockerDNS{DaemonJSON: path, DNS: []string{"172.17.0.1"}}
	if err := d.Enable(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	dns, _ := cfg["dns"].([]any)
	if len(dns) != 1 || dns[0] != "172.17.0.1" {
		t.Fatalf("%v", cfg)
	}
	if cfg["log-driver"] != "json-file" {
		t.Fatalf("lost keys: %v", cfg)
	}
	if err := d.Disable(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(orig) {
		t.Fatalf("restore: %q", got)
	}
}

func TestRedirectRemoveIdempotent(t *testing.T) {
	r := &dnsredir.Redirect{ListenHost: "127.0.0.1", ListenPort: "53"}
	// Remove without Enable should be no-op.
	if err := r.Remove(); err != nil {
		t.Fatal(err)
	}
}
