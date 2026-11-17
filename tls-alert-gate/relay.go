package main

import (
	"io"
	"net"
	"sync/atomic"
	"time"
)

type streamActivity struct {
	started time.Time
	last    atomic.Int64
}

func (a *streamActivity) mark() {
	now := time.Since(a.started).Nanoseconds()
	for previous := a.last.Load(); now > previous; previous = a.last.Load() {
		if a.last.CompareAndSwap(previous, now) {
			return
		}
	}
}

// Wrapping both interfaces keeps io.Copy from bypassing activity accounting via
// TCPConn's splice methods. Activity is needed only to expire idle half-closes.
type activeReader struct {
	reader   io.Reader
	activity *streamActivity
}

func (r activeReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 {
		r.activity.mark()
	}
	return n, err
}

type activeWriter struct {
	writer   io.Writer
	activity *streamActivity
}

func (w activeWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if n > 0 {
		w.activity.mark()
	}
	return n, err
}

// relayTCP preserves ordinary session lifetimes and half-close delivery. Once
// one direction ends, the other must make progress within halfCloseIdle. An I/O
// error closes both sides promptly. The result reports an expired half-close.
func relayTCP(client, upstream *net.TCPConn, halfCloseIdle time.Duration) bool {
	activity := &streamActivity{started: time.Now()}
	finished := make(chan error, 2)
	copyStream := func(dst, src *net.TCPConn) {
		// Bound relay buffers to 32 KiB per connection across both directions.
		buffer := make([]byte, 16*1024)
		_, err := io.CopyBuffer(activeWriter{dst, activity}, activeReader{src, activity}, buffer)
		if err == nil {
			err = dst.CloseWrite()
		}
		finished <- err
	}
	go copyStream(upstream, client)
	go copyStream(client, upstream)
	closeBoth := func() {
		client.Close()
		upstream.Close()
	}
	if err := <-finished; err != nil {
		closeBoth()
		<-finished
		return false
	}
	activity.mark()
	timer := time.NewTimer(halfCloseIdle)
	defer timer.Stop()
	for {
		select {
		case <-finished:
			return false
		case <-timer.C:
			idle := time.Since(activity.started) - time.Duration(activity.last.Load())
			if idle < halfCloseIdle {
				timer.Reset(halfCloseIdle - idle)
				continue
			}
			closeBoth()
			<-finished
			return true
		}
	}
}
