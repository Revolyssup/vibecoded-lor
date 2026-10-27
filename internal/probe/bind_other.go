//go:build !unix

package probe

import "syscall"

func bindEphemeral(network string, c syscall.RawConn) int { return 0 }
