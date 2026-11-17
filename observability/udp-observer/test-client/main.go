// Integration-only client. No credentials, accounts or application data.
package main

import (
	"context"
	"crypto/tls"
	quic "github.com/apernet/quic-go"
	"os"
	"time"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, _ := quic.DialAddr(ctx, os.Args[1], &tls.Config{ServerName: "udp-observer.example.test", NextProtos: []string{"h3"}, InsecureSkipVerify: true}, &quic.Config{HandshakeIdleTimeout: time.Second})
	if c != nil {
		c.CloseWithError(0, "")
	}
}
