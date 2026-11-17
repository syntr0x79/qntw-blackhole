//go:build !linux

package main

import (
	"context"
	"errors"
	"net"
)

func transparentListen(context.Context, string) (net.Listener, error) {
	return nil, errors.New("transparent gate requires Linux")
}
func transparentDial(context.Context, string, int, string, int) (*net.TCPConn, error) {
	return nil, errors.New("transparent gate requires Linux")
}
