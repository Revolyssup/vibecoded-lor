//go:build !linux

package probe

import (
	"net"

	"github.com/revolyssup/vibecoded-lor/internal/trace"
)

func tcpInfo(c *net.TCPConn) (headline, detail []trace.Field) { return nil, nil }
