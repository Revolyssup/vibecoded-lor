package capture

import (
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// afpacket reads layer 3 packets from a Linux AF_PACKET socket. It needs
// CAP_NET_RAW (root), and works without libpcap or cgo.
type afpacket struct {
	fd  int
	buf []byte
	oob []byte
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func open(ifindex int) (source, error) {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, errors.New("raw sockets need root or CAP_NET_RAW")
		}
		return nil, err
	}
	sll := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: ifindex}
	if err := unix.Bind(fd, sll); err != nil {
		unix.Close(fd)
		return nil, err
	}
	tv := unix.Timeval{Usec: 50_000}
	unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	// Ask the kernel to stamp each packet, so wire events line up with
	// socket events no matter how late we get to read them.
	unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1)
	return &afpacket{fd: fd, buf: make([]byte, 1<<16), oob: make([]byte, 256)}, nil
}

func (a *afpacket) next() (*packet, error) {
	n, oobn, _, from, err := unix.Recvmsg(a.fd, a.buf, a.oob, 0)
	ts := time.Now()
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return nil, nil
		}
		return nil, err
	}
	if msgs, err := unix.ParseSocketControlMessage(a.oob[:oobn]); err == nil {
		for _, m := range msgs {
			if m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_TIMESTAMPNS && len(m.Data) >= 16 {
				ts = time.Unix(int64(nativeEndian.Uint64(m.Data[0:8])), int64(nativeEndian.Uint64(m.Data[8:16])))
			}
		}
	}
	p := &packet{data: make([]byte, n), ts: ts}
	copy(p.data, a.buf[:n])
	if sll, ok := from.(*unix.SockaddrLinklayer); ok {
		p.outgoing = sll.Pkttype == unix.PACKET_OUTGOING
		p.ifindex = sll.Ifindex
	}
	return p, nil
}

func (a *afpacket) close() { unix.Close(a.fd) }

// nativeEndian is the byte order of struct timespec in control messages.
var nativeEndian binary.ByteOrder = binary.NativeEndian
