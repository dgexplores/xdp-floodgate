// SPDX-License-Identifier: Apache-2.0

package loader

// More BPF_PROG_RUN coverage for the packet parser: IPv6, VLAN, IPv4
// options, fragments and truncated frames. Needs root, like prog_test.go.

import (
	"encoding/binary"
	"testing"
)

// tcpHeader fills the 20-byte TCP header at p with the given flags.
func tcpHeader(p []byte, src, dst uint16, flags byte) {
	binary.BigEndian.PutUint16(p[0:], src)
	binary.BigEndian.PutUint16(p[2:], dst)
	p[12] = 5 << 4 // data offset
	p[13] = flags
}

// ipv6Packet builds Ethernet + IPv6 + TCP from src.
func ipv6Packet(src [16]byte, flags byte) []byte {
	p := make([]byte, 14+40+20)
	binary.BigEndian.PutUint16(p[12:], 0x86dd)
	ip6 := p[14:]
	ip6[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(ip6[4:], 20)
	ip6[6] = 6 // TCP
	ip6[7] = 64
	copy(ip6[8:], src[:])
	copy(ip6[24:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	tcpHeader(ip6[40:], 40000, 80, flags)
	return p
}

// vlanPacket inserts an 802.1Q tag between the Ethernet header and p.
func vlanPacket(p []byte, vlanID uint16) []byte {
	out := make([]byte, 0, len(p)+4)
	out = append(out, p[:12]...)
	out = append(out, 0x81, 0x00)
	out = append(out, byte(vlanID>>8), byte(vlanID))
	out = append(out, p[12:]...)
	return out
}

// ipv4OptionsPacket builds Ethernet + IPv4 (24-byte header) + TCP.
func ipv4OptionsPacket(src [4]byte, flags byte) []byte {
	p := make([]byte, 14+24+20)
	binary.BigEndian.PutUint16(p[12:], 0x0800)
	ip := p[14:]
	ip[0] = 0x46 // v4, 24-byte header
	binary.BigEndian.PutUint16(ip[2:], 44)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:], src[:])
	copy(ip[16:], []byte{10, 0, 0, 100})
	ip[20], ip[21], ip[22], ip[23] = 1, 1, 0, 0 // NOP, NOP, end of options
	tcpHeader(ip[24:], 40000, 80, flags)
	return p
}

// ipv4FragmentPacket builds Ethernet + IPv4 + bytes that look like TCP but
// belong to a non-first fragment (offset 1), so they must not be parsed as
// a TCP header.
func ipv4FragmentPacket(src [4]byte, flags byte) []byte {
	p := tcpPacket(src, flags)
	binary.BigEndian.PutUint16(p[14+6:], 1) // fragment offset, in 8-byte units
	return p
}

func TestPerIPv6Limit(t *testing.T) {
	objs := loadTestObjects(t, Limits{IP: Limit{Rate: 1, Burst: 3}})
	a := ipv6Packet([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}, ackFlag)
	if got := run(t, objs, a, 10); got != 3 {
		t.Errorf("IPv6 sender A passed %d, want 3", got)
	}
	b := ipv6Packet([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10}, ackFlag)
	if got := run(t, objs, b, 10); got != 3 {
		t.Errorf("IPv6 sender B passed %d, want 3", got)
	}
}

func TestIPv6SYNLimit(t *testing.T) {
	objs := loadTestObjects(t, Limits{SYN: Limit{Rate: 1, Burst: 2}})
	pkt := ipv6Packet([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9}, synFlag)
	if got := run(t, objs, pkt, 10); got != 2 {
		t.Errorf("IPv6 SYN passed %d, want 2", got)
	}
}

func TestVLANLimit(t *testing.T) {
	objs := loadTestObjects(t, Limits{IP: Limit{Rate: 1, Burst: 2}})
	pkt := vlanPacket(tcpPacket([4]byte{192, 0, 2, 1}, ackFlag), 42)
	if got := run(t, objs, pkt, 10); got != 2 {
		t.Errorf("VLAN-tagged sender passed %d, want 2", got)
	}
}

func TestQinQIsNotIP(t *testing.T) {
	// QinQ is deliberately not parsed: it must pass untouched, not crash.
	objs := loadTestObjects(t, Limits{IP: Limit{Rate: 1, Burst: 1}})
	outer := vlanPacket(vlanPacket(tcpPacket([4]byte{192, 0, 2, 1}, ackFlag), 1), 2)
	if got := run(t, objs, outer, 5); got != 5 {
		t.Errorf("QinQ passed %d, want 5", got)
	}
}

func TestIPv4OptionsSYN(t *testing.T) {
	// SYN detection must skip the IPv4 options, not read them as TCP.
	objs := loadTestObjects(t, Limits{SYN: Limit{Rate: 1, Burst: 2}})
	pkt := ipv4OptionsPacket([4]byte{198, 51, 100, 8}, synFlag)
	if got := run(t, objs, pkt, 10); got != 2 {
		t.Errorf("SYN with IPv4 options passed %d, want 2", got)
	}
}

func TestIPv4FragmentIsNotSYN(t *testing.T) {
	// Only the first fragment carries a TCP header; the SYN flag bits in a
	// later fragment are payload and must not consume the SYN budget.
	objs := loadTestObjects(t, Limits{SYN: Limit{Rate: 1, Burst: 1}})
	frag := ipv4FragmentPacket([4]byte{203, 0, 113, 10}, synFlag)
	if got := run(t, objs, frag, 5); got != 5 {
		t.Errorf("fragment passed %d, want 5", got)
	}
	bare := tcpPacket([4]byte{203, 0, 113, 10}, synFlag)
	if got := run(t, objs, bare, 5); got != 1 {
		t.Errorf("bare SYN passed %d, want 1", got)
	}
}

func TestTruncatedPacketsPass(t *testing.T) {
	objs := loadTestObjects(t, Limits{IP: Limit{Rate: 1, Burst: 1}, Global: Limit{Rate: 1, Burst: 1}})
	// BPF_PROG_RUN rejects frames shorter than an Ethernet header.
	for _, n := range []int{14, 20, 33} {
		if got := run(t, objs, make([]byte, n), 3); got != 3 {
			t.Errorf("%d-byte frame passed %d, want 3", n, got)
		}
	}
	stats, err := readStats(objs.Stats)
	if err != nil {
		t.Fatal(err)
	}
	if stats[4].Packets != 9 {
		t.Errorf("not_ip packets = %d, want 9", stats[4].Packets)
	}
}

func TestUDPIsLimited(t *testing.T) {
	// The per-IP limit covers every IP protocol, not just TCP.
	objs := loadTestObjects(t, Limits{IP: Limit{Rate: 1, Burst: 2}})
	p := tcpPacket([4]byte{192, 0, 2, 20}, 0)
	p[14+9] = 17 // IPPROTO_UDP
	if got := run(t, objs, p, 10); got != 2 {
		t.Errorf("UDP passed %d, want 2", got)
	}
}

func TestStatsBytes(t *testing.T) {
	objs := loadTestObjects(t, Limits{IP: Limit{Rate: 1, Burst: 1}})
	pkt := tcpPacket([4]byte{192, 0, 2, 30}, ackFlag)
	if got := run(t, objs, pkt, 2); got != 1 {
		t.Fatalf("passed %d, want 1", got)
	}
	stats, err := readStats(objs.Stats)
	if err != nil {
		t.Fatal(err)
	}
	const frame = 14 + 20 + 20
	if stats[0].Bytes != frame || stats[1].Bytes != frame {
		t.Errorf("bytes pass=%d drop_ip=%d, want %d each", stats[0].Bytes, stats[1].Bytes, frame)
	}
}
