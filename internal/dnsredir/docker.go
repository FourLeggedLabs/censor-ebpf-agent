package dnsredir

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// Enable writes dns into daemon.json and reloads docker (best-effort SIGHUP/restart).
func (d *DockerDNS) Enable() error {
	path := d.DaemonJSON
	if path == "" {
		path = DefaultDockerDaemonJSON
	}
	d.DaemonJSON = path
	if len(d.DNS) == 0 {
		return fmt.Errorf("docker dns list empty")
	}
	var cfg map[string]any
	b, err := os.ReadFile(path)
	if err == nil {
		d.hadFile = true
		d.backup = append([]byte(nil), b...)
		if err := json.Unmarshal(b, &cfg); err != nil {
			cfg = map[string]any{}
		}
	} else if os.IsNotExist(err) {
		cfg = map[string]any{}
	} else {
		return err
	}
	cfg["dns"] = d.DNS
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
		return err
	}
	_ = exec.Command("killall", "-s", "HUP", "dockerd").Run()
	d.enabled = true
	return nil
}

// Disable restores the previous daemon.json (or removes if we created it).
func (d *DockerDNS) Disable() error {
	if !d.enabled {
		return nil
	}
	path := d.DaemonJSON
	if d.hadFile {
		return os.WriteFile(path, d.backup, 0o644)
	}
	return os.Remove(path)
}
