package capture

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/revolyssup/vibecoded-lor/internal/trace"
)

const (
	out = 0
	in  = 1
)

// decoder keeps per-direction TCP state so packets can be labelled the way a
// textbook would: handshake steps, data, ACKs, retransmissions, teardown.
type decoder struct {
	isn         [2]uint32
	haveISN     [2]bool
	nextSeq     [2]uint32
	haveNext    [2]bool
	wscale      [2]int
	lastAck     [2]uint32
	lastWin     [2]uint16
	sawAck      [2]bool
	synAckSeen  bool
	established bool
}

func (d *decoder) init() { d.wscale = [2]int{-1, -1} }

func (d *decoder) decode(data []byte, remote netip.AddrPort, localPort uint16) (trace.Event, bool) {
	if len(data) == 0 {
		return trace.Event{}, false
	}
	first := layers.LayerTypeIPv4
	if data[0]>>4 == 6 {
		first = layers.LayerTypeIPv6
	} else if data[0]>>4 != 4 {
		return trace.Event{}, false
	}
	pkt := gopacket.NewPacket(data, first, gopacket.NoCopy)
	tcpL, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcpL == nil {
		return trace.Event{}, false
	}
	var src, dst netip.Addr
	var ipSec trace.Section
	if v4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		src, _ = netip.AddrFromSlice(v4.SrcIP.To4())
		dst, _ = netip.AddrFromSlice(v4.DstIP.To4())
		ipSec = ipv4Section(v4)
	} else if v6, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		src, _ = netip.AddrFromSlice(v6.SrcIP)
		dst, _ = netip.AddrFromSlice(v6.DstIP)
		ipSec = ipv6Section(v6)
	} else {
		return trace.Event{}, false
	}
	rip, rport := remote.Addr().Unmap(), remote.Port()
	sp, dp := uint16(tcpL.SrcPort), uint16(tcpL.DstPort)
	var dir int
	switch {
	case src == rip && sp == rport && (localPort == 0 || dp == localPort):
		dir = in
	case dst == rip && dp == rport && (localPort == 0 || sp == localPort):
		dir = out
	default:
		return trace.Event{}, false
	}

	title, warn := d.classify(dir, tcpL)
	ev := trace.Event{Layer: trace.LayerTCP, Dir: trace.DirOut, Title: title, Warn: warn, Note: note(tcpL),
		Sections: []trace.Section{d.tcpSection(dir, tcpL), ipSec}}
	if dir == in {
		ev.Dir = trace.DirIn
	}
	if title == "TCP handshake: ACK" {
		ev.Note = "Step 3: the client acknowledges the server's ISN. The connection is now ESTABLISHED."
	}
	return ev, true
}

func (d *decoder) classify(dir int, t *layers.TCP) (string, bool) {
	plen := uint32(len(t.Payload))
	seqLen := plen
	if t.SYN {
		seqLen++
	}
	if t.FIN {
		seqLen++
	}
	end := t.Seq + seqLen
	retrans := d.haveNext[dir] && seqLen > 0 && !seqAfter(end, d.nextSeq[dir])
	if t.SYN {
		retrans = d.haveISN[dir] && t.Seq == d.isn[dir]
		d.isn[dir], d.haveISN[dir] = t.Seq, true
		d.wscale[dir] = -1
		for _, o := range t.Options {
			if o.OptionType == layers.TCPOptionKindWindowScale && len(o.OptionData) == 1 {
				d.wscale[dir] = int(o.OptionData[0])
			}
		}
	}
	if t.SYN || !d.haveNext[dir] || seqAfter(end, d.nextSeq[dir]) {
		d.nextSeq[dir], d.haveNext[dir] = end, true
	}
	dup := false
	if t.ACK && plen == 0 && !t.SYN && !t.FIN && !t.RST {
		dup = d.sawAck[dir] && t.Ack == d.lastAck[dir] && t.Window == d.lastWin[dir] && d.established
	}
	if t.ACK {
		d.lastAck[dir], d.lastWin[dir], d.sawAck[dir] = t.Ack, t.Window, true
	}

	switch {
	case t.RST:
		return "TCP RST (connection reset)", true
	case t.SYN && !t.ACK:
		if retrans {
			return "TCP handshake: SYN (retransmission)", true
		}
		return "TCP handshake: SYN", false
	case t.SYN && t.ACK:
		d.synAckSeen = true
		if retrans {
			return "TCP handshake: SYN-ACK (retransmission)", true
		}
		return "TCP handshake: SYN-ACK", false
	case t.FIN:
		s := "TCP FIN (closing)"
		if plen > 0 {
			s = fmt.Sprintf("TCP FIN + %dB data", plen)
		}
		return s, false
	case retrans:
		return fmt.Sprintf("TCP retransmission %dB", plen), true
	case plen > 0:
		return fmt.Sprintf("TCP data %dB%s", plen, payloadHint(t.Payload)), false
	case dir == out && d.synAckSeen && !d.established:
		d.established = true
		return "TCP handshake: ACK", false
	case dup:
		return "TCP duplicate ACK", true
	}
	return "TCP ACK", false
}

func note(t *layers.TCP) string {
	switch {
	case t.RST:
		return "RST aborts the connection: the port is closed, the peer gave up, or data arrived after a socket was already closed."
	case t.SYN && !t.ACK:
		return "Step 1 of the 3-way handshake: the client picks its initial sequence number and proposes options (MSS, window scale, SACK)."
	case t.SYN && t.ACK:
		return "Step 2: the server acknowledges the client's ISN and sends its own."
	case t.FIN:
		return "This side has no more data to send; the other side may still send until it sends its own FIN."
	}
	return ""
}

// seqAfter reports a > b in 32-bit sequence space.
func seqAfter(a, b uint32) bool { return int32(a-b) > 0 }

func payloadHint(p []byte) string {
	if len(p) >= 3 && p[1] == 3 && p[0] >= 20 && p[0] <= 23 {
		return [...]string{" (TLS ChangeCipherSpec)", " (TLS Alert)", " (TLS Handshake)", " (TLS AppData)"}[p[0]-20]
	}
	s := string(p[:min(len(p), 8)])
	for _, m := range []string{"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI", "HTTP"} {
		if strings.HasPrefix(s, m) {
			return " (HTTP)"
		}
	}
	return ""
}

func (d *decoder) tcpSection(dir int, t *layers.TCP) trace.Section {
	other := 1 - dir
	rel := func(v uint32, side int) string {
		if !d.haveISN[side] {
			return fmt.Sprint(v)
		}
		return fmt.Sprintf("%d (relative)", v-d.isn[side])
	}
	ack := "—"
	if t.ACK {
		ack = rel(t.Ack, other)
	}
	win := fmt.Sprintf("%d bytes", t.Window)
	if !t.SYN && d.wscale[dir] >= 0 && d.wscale[other] >= 0 {
		win = fmt.Sprintf("%d bytes (%d × 2^%d)", int(t.Window)<<d.wscale[dir], t.Window, d.wscale[dir])
	}
	payload := fmt.Sprintf("%d bytes%s", len(t.Payload), payloadHint(t.Payload))
	return trace.Section{Layer: trace.LayerTCP, Title: "TCP segment", Fields: []trace.Field{
		{K: "Ports", V: fmt.Sprintf("%d → %d", t.SrcPort, t.DstPort)},
		{K: "Flags", V: flags(t)},
		{K: "Seq", V: rel(t.Seq, dir)},
		{K: "Ack", V: ack},
		{K: "Window", V: win},
		{K: "Payload", V: payload},
	}, Detail: []trace.Field{
		{K: "Raw seq / ack", V: fmt.Sprintf("%d / %d", t.Seq, t.Ack)},
		{K: "Header length", V: fmt.Sprintf("%d bytes", int(t.DataOffset)*4)},
		{K: "Options", V: options(t)},
		{K: "Checksum", V: fmt.Sprintf("0x%04x", t.Checksum)},
	}}
}

func flags(t *layers.TCP) string {
	var f []string
	for _, x := range []struct {
		on bool
		n  string
	}{{t.SYN, "SYN"}, {t.ACK, "ACK"}, {t.PSH, "PSH"}, {t.FIN, "FIN"}, {t.RST, "RST"}, {t.URG, "URG"}, {t.ECE, "ECE"}, {t.CWR, "CWR"}} {
		if x.on {
			f = append(f, x.n)
		}
	}
	return strings.Join(f, ", ")
}

func options(t *layers.TCP) string {
	var o []string
	for _, x := range t.Options {
		switch x.OptionType {
		case layers.TCPOptionKindMSS:
			if len(x.OptionData) == 2 {
				o = append(o, fmt.Sprintf("MSS=%d", binary.BigEndian.Uint16(x.OptionData)))
			}
		case layers.TCPOptionKindWindowScale:
			if len(x.OptionData) == 1 {
				o = append(o, fmt.Sprintf("WScale=%d", x.OptionData[0]))
			}
		case layers.TCPOptionKindSACKPermitted:
			o = append(o, "SACK permitted")
		case layers.TCPOptionKindSACK:
			o = append(o, "SACK")
		case layers.TCPOptionKindTimestamps:
			if len(x.OptionData) == 8 {
				o = append(o, fmt.Sprintf("TS val=%d ecr=%d", binary.BigEndian.Uint32(x.OptionData), binary.BigEndian.Uint32(x.OptionData[4:])))
			}
		case layers.TCPOptionKindNop, layers.TCPOptionKindEndList:
		default:
			o = append(o, x.OptionType.String())
		}
	}
	if len(o) == 0 {
		return "(none)"
	}
	return strings.Join(o, ", ")
}

func ipv4Section(ip *layers.IPv4) trace.Section {
	fl := []string{}
	if ip.Flags&layers.IPv4DontFragment != 0 {
		fl = append(fl, "DF")
	}
	if ip.Flags&layers.IPv4MoreFragments != 0 {
		fl = append(fl, "MF")
	}
	return trace.Section{Layer: trace.LayerIP, Title: "IPv4 packet", Fields: []trace.Field{
		{K: "Version", V: "IPv4"},
		{K: "Source", V: ip.SrcIP.String()},
		{K: "Destination", V: ip.DstIP.String()},
		{K: "TTL", V: fmt.Sprint(ip.TTL)},
		{K: "Protocol", V: fmt.Sprintf("%s (%d)", ip.Protocol, uint8(ip.Protocol))},
		{K: "Total length", V: fmt.Sprintf("%d bytes", ip.Length)},
	}, Detail: []trace.Field{
		{K: "Header length", V: fmt.Sprintf("%d bytes", int(ip.IHL)*4)},
		{K: "DSCP / ECN", V: fmt.Sprintf("%d / %d", ip.TOS>>2, ip.TOS&3)},
		{K: "Identification", V: fmt.Sprintf("0x%04x", ip.Id)},
		{K: "Flags", V: orDash(strings.Join(fl, ", "))},
		{K: "Fragment offset", V: fmt.Sprint(ip.FragOffset)},
		{K: "Checksum", V: fmt.Sprintf("0x%04x", ip.Checksum)},
	}}
}

func ipv6Section(ip *layers.IPv6) trace.Section {
	return trace.Section{Layer: trace.LayerIP, Title: "IPv6 packet", Fields: []trace.Field{
		{K: "Version", V: "IPv6"},
		{K: "Source", V: ip.SrcIP.String()},
		{K: "Destination", V: ip.DstIP.String()},
		{K: "Hop limit", V: fmt.Sprint(ip.HopLimit)},
		{K: "Next header", V: fmt.Sprintf("%s (%d)", ip.NextHeader, uint8(ip.NextHeader))},
		{K: "Payload length", V: fmt.Sprintf("%d bytes", ip.Length)},
	}, Detail: []trace.Field{
		{K: "Traffic class", V: fmt.Sprint(ip.TrafficClass)},
		{K: "Flow label", V: fmt.Sprintf("0x%05x", ip.FlowLabel)},
	}}
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
