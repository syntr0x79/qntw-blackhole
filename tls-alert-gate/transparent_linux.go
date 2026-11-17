//go:build linux

package main

import (
	"context"
	"net"
	"syscall"
)

const ipv6Transparent = 75

func transparentControl(mark int, listening, ipv6 bool) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var inner error
		e := c.Control(func(fd uintptr) {
			if ipv6 {
				inner = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, ipv6Transparent, 1)
			} else {
				inner = syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
			}
			if inner != nil {
				return
			}
			if mark != 0 {
				inner = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
			}
			if inner == nil && !listening {
				inner = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			}
			if inner != nil {
				return
			}
			if listening && ipv6 {
				inner = syscall.SetsockoptInt(int(fd), syscall.SOL_IPV6, syscall.IPV6_V6ONLY, 1)
			}
		})
		if e != nil {
			return e
		}
		return inner
	}
}
func transparentListen(ctx context.Context, address string) (net.Listener, error) {
	host, _, e := net.SplitHostPort(address)
	if e != nil {
		return nil, e
	}
	v6 := net.ParseIP(host).To4() == nil
	network := "tcp4"
	if v6 {
		network = "tcp6"
	}
	lc := net.ListenConfig{Control: transparentControl(0, true, v6)}
	return lc.Listen(ctx, network, address)
}
func transparentDial(ctx context.Context, source string, port int, backend string, mark int) (*net.TCPConn, error) {
	ip := net.ParseIP(source)
	v6 := ip.To4() == nil
	network := "tcp4"
	if v6 {
		network = "tcp6"
	}
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: ip, Port: port}, Control: transparentControl(mark, false, v6)}
	c, e := d.DialContext(ctx, network, backend)
	if e != nil {
		return nil, e
	}
	return c.(*net.TCPConn), nil
}
