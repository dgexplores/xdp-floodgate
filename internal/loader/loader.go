// SPDX-License-Identifier: Apache-2.0

// Package loader loads the XDP program, attaches it to an interface and
// exposes its maps (limits, stats) to the CLI.
//
// Everything is pinned under PinDir on bpffs. A pin is a file that keeps a
// kernel BPF object alive after the creating process exits, so:
//   - `floodgate start` can attach and exit; the filter keeps running.
//   - status / set-limit are separate processes that open the pinned maps.
//   - a crashing control plane never removes protection.
package loader

//go:generate go tool bpf2go -cc clang -target bpfel -type fg_config -type fg_datarec floodgate ../../bpf/floodgate.c

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/wasvaibhav/xdp-floodgate/internal/limiter"
)

const PinDir = "/sys/fs/bpf/floodgate"

var linkPin = filepath.Join(PinDir, "xdp_link")

// Limit is one rate limit in human units. Rate 0 = unlimited.
type Limit struct{ Rate, Burst uint64 }

type Limits struct {
	IP     Limit // all packets per source IP
	SYN    Limit // TCP SYNs per source IP
	Global Limit // all packets for the whole node
}

// StatNames matches the order of enum fg_stat in bpf/floodgate.c.
var StatNames = []string{"pass", "drop_ip", "drop_syn", "drop_global", "not_ip"}

type Counter struct{ Packets, Bytes uint64 }

// Start loads the program, writes the initial limits, attaches to iface
// and pins everything. generic forces the slower skb-mode XDP, needed on
// NICs/veths without native XDP support.
func Start(iface string, maxIPs uint32, generic bool, lim Limits) error {
	if _, err := os.Stat(linkPin); err == nil {
		return errors.New("already attached (run `floodgate stop` first)")
	}
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(PinDir, 0o700); err != nil {
		return fmt.Errorf("%w (is bpffs mounted at /sys/fs/bpf?)", err)
	}

	spec, err := loadFloodgate()
	if err != nil {
		return err
	}
	spec.Maps["ip_state"].MaxEntries = maxIPs

	var objs floodgateObjects
	// PinPath: maps marked LIBBPF_PIN_BY_NAME are created and pinned there.
	err = spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: PinDir},
	})
	if err != nil {
		// Verifier errors are long; %+v prints the full verifier log.
		return fmt.Errorf("loading BPF objects: %+v", err)
	}
	// Closing our fds is fine: pins keep the maps (and the link, the prog).
	defer objs.Close()

	if err := objs.Config.Put(uint32(0), toConfig(lim)); err != nil {
		return err
	}

	flags := link.XDPAttachFlags(0) // 0 = native if the driver supports it
	if generic {
		flags = link.XDPGenericMode
	}
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFloodgate,
		Interface: ifc.Index,
		Flags:     flags,
	})
	if err != nil {
		return fmt.Errorf("attaching XDP to %s: %w", iface, err)
	}
	defer l.Close()
	return l.Pin(linkPin)
}

// Stop detaches the program and deletes all pinned state.
func Stop() error {
	l, err := link.LoadPinnedLink(linkPin, nil)
	if err == nil {
		// Removing the last reference to the link detaches the program.
		err = errors.Join(l.Unpin(), l.Close())
	} else if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return errors.Join(err, os.RemoveAll(PinDir))
}

// GetLimits reads the live limits.
func GetLimits() (Limits, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinDir, "config"), nil)
	if err != nil {
		return Limits{}, err
	}
	defer m.Close()
	var c floodgateFgConfig
	if err := m.Lookup(uint32(0), &c); err != nil {
		return Limits{}, err
	}
	return Limits{
		IP:     Limit{c.Ip.Rate, c.Ip.Burst},
		SYN:    Limit{c.Syn.Rate, c.Syn.Burst},
		Global: Limit{c.Global.Rate, c.Global.Burst},
	}, nil
}

// SetLimits replaces the live limits. The XDP program sees the new values
// on its very next packet; no reload, no dropped connections.
func SetLimits(lim Limits) error {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinDir, "config"), nil)
	if err != nil {
		return err
	}
	defer m.Close()
	return m.Put(uint32(0), toConfig(lim))
}

// Stats sums the per-CPU counters.
func Stats() ([]Counter, error) {
	m, err := ebpf.LoadPinnedMap(filepath.Join(PinDir, "stats"), nil)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	return readStats(m)
}

func readStats(m *ebpf.Map) ([]Counter, error) {
	out := make([]Counter, len(StatNames))
	for i := range out {
		var perCPU []floodgateFgDatarec // per-CPU maps return one value per CPU
		if err := m.Lookup(uint32(i), &perCPU); err != nil {
			return nil, err
		}
		for _, r := range perCPU {
			out[i].Packets += r.Packets
			out[i].Bytes += r.Bytes
		}
	}
	return out, nil
}

func toConfig(l Limits) floodgateFgConfig {
	var c floodgateFgConfig
	c.Ip.Rate, c.Ip.Burst = l.IP.Rate, l.IP.Burst
	c.Ip.IntervalNs, c.Ip.ToleranceNs = limiter.GCRA(l.IP.Rate, l.IP.Burst, 1)
	c.Syn.Rate, c.Syn.Burst = l.SYN.Rate, l.SYN.Burst
	c.Syn.IntervalNs, c.Syn.ToleranceNs = limiter.GCRA(l.SYN.Rate, l.SYN.Burst, 1)
	c.Global.Rate, c.Global.Burst = l.Global.Rate, l.Global.Burst
	// ponytail: splits evenly over all CPUs; if RSS steers traffic to only a
	// few RX queues, the effective cap is lower. Shard by RX-queue count then.
	c.Global.IntervalNs, c.Global.ToleranceNs = limiter.GCRA(l.Global.Rate, l.Global.Burst, runtime.NumCPU())
	return c
}
