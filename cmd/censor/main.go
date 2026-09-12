package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/agent"
	"github.com/FourLeggedLabs/ebpf-firewall-agent/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(version.String())
	case "start":
		os.Exit(runStart(os.Args[2:]))
	case "stop":
		os.Exit(runStop(os.Args[2:]))
	case "wait-ready":
		os.Exit(runWaitReady(os.Args[2:]))
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: censor <start|stop|wait-ready|version> [flags]\n")
}

func runStart(args []string) int {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	apiURL := fs.String("api-url", os.Getenv("CENSOR_API_URL"), "Censor API base URL")
	apiKey := fs.String("api-key-file", agent.DefaultAPIKeyPath, "path to API key")
	config := fs.String("config", os.Getenv("CENSOR_CONFIG_FILE"), "local protojson policy (bypass API)")
	logPath := fs.String("log", "", "NDJSON log path")
	dnsListen := fs.String("dns-listen", "127.0.0.1:5353", "local DNS listen address")
	dnsUp := fs.String("dns-upstream", "8.8.8.8:53", "upstream DNS")
	ready := fs.String("ready-file", agent.DefaultReadyFile, "ready sentinel")
	fail := fs.String("failure-file", agent.DefaultFailureFile, "failure sentinel")
	pid := fs.String("pidfile", agent.DefaultPidFile, "pid file")
	gha := fs.Bool("github-actions", false, "GitHub Actions preset")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg := agent.Config{
		APIURL:        *apiURL,
		APIKeyPath:    *apiKey,
		ConfigFile:    *config,
		LogPath:       *logPath,
		DNSListen:     *dnsListen,
		DNSUpstream:   *dnsUp,
		ReadyFile:     *ready,
		FailureFile:   *fail,
		PidFile:       *pid,
		GitHubActions: *gha,
	}
	if *gha {
		cfg.DNSListen = "127.0.0.1:53"
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rt, err := agent.Start(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "start: %v\n", err)
		return 1
	}
	<-ctx.Done()
	upCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := rt.Upload(upCtx, "success"); err != nil {
		fmt.Fprintf(os.Stderr, "upload: %v\n", err)
	}
	if err := rt.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close: %v\n", err)
		return 1
	}
	return 0
}

func runStop(args []string) int {
	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	pidFile := fs.String("pidfile", agent.DefaultPidFile, "pid file")
	status := fs.String("status", "success", "job status for upload metadata")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	_ = status
	b, err := os.ReadFile(*pidFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pidfile: %v\n", err)
		return 1
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "pid: %v\n", err)
		return 1
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "kill: %v\n", err)
		return 1
	}
	return 0
}

func runWaitReady(args []string) int {
	fs := flag.NewFlagSet("wait-ready", flag.ContinueOnError)
	ready := fs.String("ready-file", agent.DefaultReadyFile, "ready sentinel")
	fail := fs.String("failure-file", agent.DefaultFailureFile, "failure sentinel")
	timeout := fs.Duration("timeout", 30*time.Second, "timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := agent.WaitReady(*ready, *fail, *timeout); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	return 0
}
