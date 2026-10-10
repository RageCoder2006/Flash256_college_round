package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/41vi4p/avhsol/core/internal/netmux"
)

// cmdNetFwd runs INSIDE a gVisor container (see internal/cliagent/gvisor.go). The container has no network; this
// listens on 127.0.0.1 for the allowed ports and tunnels each connection over stdio to the host, then runs the agent
// command and reports its output and exit status over the same channel. Nothing else leaves the container.
func cmdNetFwd(args []string) error {
	fs := flag.NewFlagSet("netfwd", flag.ExitOnError)
	ports := fs.String("ports", "", "comma-separated ports to tunnel")
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) == 0 {
		return fmt.Errorf("usage: avhsol netfwd -ports a,b -- command args...")
	}
	var ps []int
	for _, p := range strings.Split(*ports, ",") {
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return fmt.Errorf("bad port %q", p)
		}
		ps = append(ps, n)
	}
	code, err := netmux.RunContainer(context.Background(), "127.0.0.1", ps, rest, os.Stdin, os.Stdout)
	if err != nil {
		return err
	}
	os.Exit(code)
	return nil
}
