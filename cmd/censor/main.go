package main

import (
	"fmt"
	"os"

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
	case "start", "stop", "wait-ready":
		fmt.Fprintf(os.Stderr, "censor %s: %s not implemented yet\n", version.String(), os.Args[1])
		os.Exit(1)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: censor <start|stop|wait-ready|version>\n")
}
