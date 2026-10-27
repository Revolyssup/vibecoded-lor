//go:build unix

package probe

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// bindEphemeral binds the socket to an ephemeral port before connect() so
// the packet capture knows our local port before the SYN leaves.
func bindEphemeral(network string, c syscall.RawConn) (port int) {
	c.Control(func(fd uintptr) {
		var sa unix.Sockaddr = &unix.SockaddrInet4{}
		if network == "tcp6" {
			sa = &unix.SockaddrInet6{}
		}
		if unix.Bind(int(fd), sa) != nil {
			return
		}
		got, err := unix.Getsockname(int(fd))
		if err != nil {
			return
		}
		switch a := got.(type) {
		case *unix.SockaddrInet4:
			port = a.Port
		case *unix.SockaddrInet6:
			port = a.Port
		}
	})
	return port
}
