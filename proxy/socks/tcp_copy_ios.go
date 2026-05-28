//go:build ios

package socks

import (
	"io"
	"net"

	"github.com/eycorsican/go-tun2socks/core"
)

// Default io.Copy buffer is 32 KiB & pinned (kept for idle sockets).
// We reduce it down to 2 KiB to trade RAM for syscall overhead on iOS.
//
// iOS has no working splice() from TCP to TCP, so we have to ensure that
// net.(*TCPConn).writeTo() called by io.CopyBuffer() does not fallback
// to io.Copy() with 32 KiB buffer -- dumb* wrappers do this.  See also:
// - https://github.com/golang/go/issues/32276
// - https://github.com/golang/go/issues/32306

type dumbReader struct{ io.Reader }
type dumbWriter struct{ io.Writer }

func tcpCopy(lhs, rhs net.Conn) (int64, error) {
	buf := core.NewBytes(core.BufSize)
	defer core.FreeBytes(buf)
	return io.CopyBuffer(dumbWriter{lhs}, dumbReader{rhs}, buf)
}
