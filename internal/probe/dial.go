// Package probe performs the actual requests and reports what happens at
// each layer to a trace.Tracer.
package probe

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/revolyssup/vibecoded-lor/internal/capture"
	"github.com/revolyssup/vibecoded-lor/internal/trace"
)

// DialOptions controls name resolution, connection and capture.
type DialOptions struct {
	Family  string            // "", "4" or "6"
	Resolve string            // optional fixed address for the host, like curl --resolve
	Capture *capture.Capturer // opened by the caller, nil without capture
	Timeout time.Duration
}

// link is an established, observed TCP connection.
type link struct {
	conn   *net.TCPConn
	cap    *capture.Capturer
	remote netip.AddrPort
	local  netip.AddrPort
}

// stop closes the capture after giving the kernel a moment to finish the
// teardown so the FIN/ACK exchange is seen.
func (l *link) stop(linger time.Duration) {
	if l.cap != nil {
		time.Sleep(linger)
		l.cap.Stop()
	}
}

func resolve(ctx context.Context, tr *trace.Tracer, host string, o DialOptions) (netip.Addr, error) {
	if o.Resolve != "" {
		a, err := netip.ParseAddr(o.Resolve)
		if err != nil {
			return a, fmt.Errorf("bad --resolve address: %w", err)
		}
		tr.Emit(trace.Event{Layer: trace.LayerDNS, Title: "DNS skipped (--resolve)", Sections: []trace.Section{{
			Layer: trace.LayerDNS, Title: "Name resolution", Fields: []trace.Field{{K: "Host", V: host}, {K: "Address", V: a.String()}}}}})
		return a, nil
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap(), nil
	}
	tr.PhaseStart("DNS lookup")
	tr.Emit(trace.Event{Layer: trace.LayerDNS, Dir: trace.DirOut, Title: "DNS lookup " + host})
	start := time.Now()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	tr.PhaseEnd("DNS lookup")
	if err != nil {
		tr.Emit(trace.Event{Layer: trace.LayerDNS, Dir: trace.DirIn, Title: "DNS lookup failed", Warn: true, Note: err.Error()})
		return netip.Addr{}, err
	}
	var v4, v6, all []string
	var pick netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		all = append(all, a.String())
		if a.Is4() {
			v4 = append(v4, a.String())
		} else {
			v6 = append(v6, a.String())
		}
		ok := o.Family == "" && a.Is4() || o.Family == "4" && a.Is4() || o.Family == "6" && a.Is6()
		if !pick.IsValid() && ok {
			pick = a
		}
	}
	if !pick.IsValid() && o.Family == "" && len(addrs) > 0 {
		pick = addrs[0].Unmap()
	}
	if !pick.IsValid() {
		return pick, fmt.Errorf("%s has no IPv%s address", host, o.Family)
	}
	tr.Emit(trace.Event{Layer: trace.LayerDNS, Dir: trace.DirIn, Title: "DNS answer " + pick.String(), Sections: []trace.Section{{
		Layer: trace.LayerDNS, Title: "Name resolution", Fields: []trace.Field{
			{K: "Host", V: host},
			{K: "A (IPv4)", V: orNone(strings.Join(v4, ", "))},
			{K: "AAAA (IPv6)", V: orNone(strings.Join(v6, ", "))},
			{K: "Using", V: pick.String()},
			{K: "Took", V: time.Since(start).Round(time.Microsecond).String()},
		}}}})
	return pick, nil
}

// dial resolves host, starts the packet capture and opens the TCP connection.
func dial(ctx context.Context, tr *trace.Tracer, host string, port int, o DialOptions) (*link, error) {
	addr, err := resolve(ctx, tr, host, o)
	if err != nil {
		return nil, err
	}
	l := &link{remote: netip.AddrPortFrom(addr, uint16(port))}

	if l.cap = o.Capture; l.cap != nil {
		l.cap.Watch(l.remote, tr)
	}

	network := "tcp4"
	if addr.Is6() {
		network = "tcp6"
	}
	d := net.Dialer{Timeout: o.Timeout, Control: func(nw, a string, c syscall.RawConn) error {
		p := bindEphemeral(nw, c)
		if l.cap != nil {
			l.cap.SetLocalPort(p)
			return nil
		}
		src := "?"
		if p != 0 {
			src = fmt.Sprint(p)
		}
		tr.Emit(trace.Event{Layer: trace.LayerTCP, Dir: trace.DirOut, Title: "TCP handshake: SYN (inferred)",
			Note: "connect() called; the kernel sends SYN and waits for SYN-ACK", Sections: []trace.Section{
				{Layer: trace.LayerTCP, Title: "TCP segment", Fields: []trace.Field{{K: "Ports", V: fmt.Sprintf("%s → %d", src, port)}, {K: "Flags", V: "SYN"}, {K: "Seq", V: "0 (relative)"}}},
				ipSection(netip.Addr{}, addr),
			}})
		return nil
	}}
	tr.PhaseStart("TCP connect")
	c, err := d.DialContext(ctx, network, l.remote.String())
	tr.PhaseEnd("TCP connect")
	if err != nil {
		tr.Emit(trace.Event{Layer: trace.LayerTCP, Title: "TCP connect failed", Warn: true, Note: err.Error()})
		l.stop(100 * time.Millisecond)
		return nil, err
	}
	l.conn = c.(*net.TCPConn)
	l.local = c.LocalAddr().(*net.TCPAddr).AddrPort()
	if l.cap != nil {
		l.cap.SetLocalPort(int(l.local.Port()))
	}

	ports := fmt.Sprintf("%d → %d", l.local.Port(), port)
	ip := ipSection(l.local.Addr().Unmap(), addr)
	head, detail := tcpInfo(l.conn)
	tcpSec := trace.Section{Layer: trace.LayerTCP, Title: "TCP connection", Fields: append([]trace.Field{{K: "Ports", V: ports}}, head...), Detail: detail}
	if l.cap == nil {
		tr.Emit(trace.Event{Layer: trace.LayerTCP, Dir: trace.DirIn, Title: "TCP handshake: SYN-ACK (inferred)", Sections: []trace.Section{
			{Layer: trace.LayerTCP, Title: "TCP segment", Fields: []trace.Field{{K: "Ports", V: fmt.Sprintf("%d → %d", port, l.local.Port())}, {K: "Flags", V: "SYN, ACK"}, {K: "Seq", V: "0 (relative)"}, {K: "Ack", V: "1 (relative)"}}},
			ipSection(addr, l.local.Addr().Unmap())}})
		tr.Emit(trace.Event{Layer: trace.LayerTCP, Dir: trace.DirOut, Title: "TCP handshake: ACK (inferred)", Sections: []trace.Section{
			{Layer: trace.LayerTCP, Title: "TCP segment", Fields: []trace.Field{{K: "Ports", V: ports}, {K: "Flags", V: "ACK"}, {K: "Seq", V: "1 (relative)"}, {K: "Ack", V: "1 (relative)"}}}, ip}})
	}
	tr.Emit(trace.Event{Layer: trace.LayerTCP, Title: "TCP connection established", Sections: []trace.Section{tcpSec, ip}})
	return l, nil
}

func ipSection(src, dst netip.Addr) trace.Section {
	v := "IPv4"
	if dst.Is6() {
		v = "IPv6"
	}
	s := "(chosen by kernel)"
	if src.IsValid() {
		s = src.String()
	}
	return trace.Section{Layer: trace.LayerIP, Title: v + " endpoints", Fields: []trace.Field{
		{K: "Version", V: v}, {K: "Source", V: s}, {K: "Destination", V: dst.String()}, {K: "Protocol", V: "TCP (6)"},
	}}
}

// socketStats reports the kernel's view of the connection near the end.
func socketStats(tr *trace.Tracer, l *link) {
	head, detail := tcpInfo(l.conn)
	if head == nil {
		return
	}
	tr.Emit(trace.Event{Layer: trace.LayerTCP, Title: "TCP socket stats (kernel TCP_INFO)", Sections: []trace.Section{{
		Layer: trace.LayerTCP, Title: "TCP connection", Fields: append([]trace.Field{{K: "Ports", V: fmt.Sprintf("%d → %d", l.local.Port(), l.remote.Port())}}, head...), Detail: detail}}})
}
