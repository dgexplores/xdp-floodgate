// SPDX-License-Identifier: Apache-2.0

// floodgate: attach, inspect and tune the XDP overload filter.
//
//	floodgate start -iface eth0 [limit flags]
//	floodgate status
//	floodgate set-limit -ip-rate 500
//	floodgate stop
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"text/tabwriter"

	"github.com/wasvaibhav/xdp-floodgate/internal/loader"
)

const usage = `usage: floodgate <start|stop|status|set-limit> [flags]
run "floodgate <command> -h" for flags`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "start":
		err = start(args)
	case "stop":
		err = loader.Stop()
	case "status":
		err = status()
	case "set-limit":
		err = setLimit(args)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "floodgate:", err)
		os.Exit(1)
	}
}

// limitFlags registers the limit flags on fs, defaulting to cur.
func limitFlags(fs *flag.FlagSet, cur *loader.Limits) {
	fs.Uint64Var(&cur.IP.Rate, "ip-rate", cur.IP.Rate, "packets/sec per source IP (0 = off)")
	fs.Uint64Var(&cur.IP.Burst, "ip-burst", cur.IP.Burst, "burst per source IP, packets")
	fs.Uint64Var(&cur.SYN.Rate, "syn-rate", cur.SYN.Rate, "TCP SYNs/sec per source IP (0 = off)")
	fs.Uint64Var(&cur.SYN.Burst, "syn-burst", cur.SYN.Burst, "SYN burst per source IP")
	fs.Uint64Var(&cur.Global.Rate, "global-pps", cur.Global.Rate, "packets/sec for the whole node (0 = off)")
	fs.Uint64Var(&cur.Global.Burst, "global-burst", cur.Global.Burst, "node-wide burst, packets")
}

func start(args []string) error {
	// Defaults are deliberately generous: behind carrier-grade NAT hundreds
	// of real users can share one IP. Tune down per service.
	lim := loader.Limits{
		IP:  loader.Limit{Rate: 1000, Burst: 2000},
		SYN: loader.Limit{Rate: 50, Burst: 100},
	}
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	iface := fs.String("iface", "", "interface to protect (required)")
	maxIPs := fs.Uint64("max-ips", 2_000_000, "source IPs tracked; least recently seen evicted beyond this (~100 B each)")
	generic := fs.Bool("generic", false, "force generic (skb) XDP mode, for NICs/veths without native XDP")
	limitFlags(fs, &lim)
	fs.Parse(args)
	if *iface == "" {
		return fmt.Errorf("-iface is required")
	}
	if *maxIPs == 0 || *maxIPs > math.MaxUint32 {
		return fmt.Errorf("-max-ips must be between 1 and %d", uint64(math.MaxUint32))
	}
	if err := loader.Start(*iface, uint32(*maxIPs), *generic, lim); err != nil {
		return err
	}
	fmt.Printf("attached to %s, state pinned in %s\n", *iface, loader.PinDir)
	return nil
}

func setLimit(args []string) error {
	// Start from the live values so unspecified flags stay unchanged.
	lim, err := loader.GetLimits()
	if err != nil {
		return fmt.Errorf("reading limits (is floodgate started?): %w", err)
	}
	fs := flag.NewFlagSet("set-limit", flag.ExitOnError)
	limitFlags(fs, &lim)
	fs.Parse(args)
	return loader.SetLimits(lim)
}

func status() error {
	lim, err := loader.GetLimits()
	if err != nil {
		return fmt.Errorf("not running? %w", err)
	}
	stats, err := loader.Stats()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "LIMIT\tRATE/s\tBURST")
	for _, l := range []struct {
		name string
		loader.Limit
	}{{"per-ip", lim.IP}, {"syn", lim.SYN}, {"global", lim.Global}} {
		fmt.Fprintf(w, "%s\t%s\t%d\n", l.name, rate(l.Rate), l.Burst)
	}
	fmt.Fprintln(w, "\nVERDICT\tPACKETS\tBYTES")
	for i, c := range stats {
		fmt.Fprintf(w, "%s\t%d\t%d\n", loader.StatNames[i], c.Packets, c.Bytes)
	}
	return w.Flush()
}

func rate(r uint64) string {
	if r == 0 {
		return "off"
	}
	return fmt.Sprint(r)
}
