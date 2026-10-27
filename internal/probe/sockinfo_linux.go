package probe

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"

	"github.com/revolyssup/vibecoded-lor/internal/trace"
)

var tcpStates = []string{"", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
	"TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK", "LISTEN", "CLOSING"}

// tcpInfo reads the kernel's TCP_INFO for the socket.
func tcpInfo(c *net.TCPConn) (headline, detail []trace.Field) {
	rc, err := c.SyscallConn()
	if err != nil {
		return nil, nil
	}
	var info *unix.TCPInfo
	rc.Control(func(fd uintptr) {
		info, err = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	})
	if err != nil || info == nil {
		return nil, nil
	}
	state := fmt.Sprint(info.State)
	if int(info.State) < len(tcpStates) {
		state = tcpStates[info.State]
	}
	us := func(v uint32) string { return (time.Duration(v) * time.Microsecond).String() }
	headline = []trace.Field{
		{K: "State", V: state},
		{K: "Smoothed RTT", V: fmt.Sprintf("%s (±%s)", us(info.Rtt), us(info.Rttvar))},
		{K: "MSS", V: fmt.Sprintf("send %d / recv %d bytes", info.Snd_mss, info.Rcv_mss)},
		{K: "Retransmits", V: fmt.Sprint(info.Total_retrans)},
	}
	detail = []trace.Field{
		{K: "Congestion window", V: fmt.Sprintf("%d segments", info.Snd_cwnd)},
		{K: "Path MTU", V: fmt.Sprint(info.Pmtu)},
		{K: "Segments out/in", V: fmt.Sprintf("%d / %d", info.Segs_out, info.Segs_in)},
		{K: "Bytes acked/received", V: fmt.Sprintf("%d / %d", info.Bytes_acked, info.Bytes_received)},
		{K: "Min RTT", V: us(info.Min_rtt)},
	}
	return headline, detail
}
