//go:build !ios

package socks

import (
	"io"
	"net"
)

func tcpCopy(lhs, rhs net.Conn) (int64, error) {
	return io.Copy(lhs, rhs)
}
