package main

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dialed, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := listener.AcceptTCP()
	if err != nil {
		dialed.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { dialed.Close(); accepted.Close() })
	return dialed, accepted
}

func startRelay(t *testing.T, idle time.Duration) (*net.TCPConn, *net.TCPConn, <-chan bool) {
	t.Helper()
	client, inbound := tcpPair(t)
	backend, outbound := tcpPair(t)
	done := make(chan bool, 1)
	go func() { done <- relayTCP(inbound, outbound, idle) }()
	return client, backend, done
}

func relayResult(t *testing.T, done <-chan bool, wantExpired bool) {
	t.Helper()
	select {
	case expired := <-done:
		if expired != wantExpired {
			t.Fatalf("half-close expired = %v, want %v", expired, wantExpired)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay retained a finished connection")
	}
}

func TestRelayReleasesSlotAfterBackendClosesAndClientStaysOpen(t *testing.T) {
	client, backend, done := startRelay(t, 100*time.Millisecond)
	backend.Close()
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("backend close did not reach client: %v", err)
	}
	// The client retains its write side. This previously held the relay forever.
	relayResult(t, done, true)
}

func TestRelayDoesNotExpireOrdinaryIdleSessions(t *testing.T) {
	idle := 100 * time.Millisecond
	client, backend, done := startRelay(t, idle)
	time.Sleep(3 * idle)
	select {
	case <-done:
		t.Fatal("ordinary session expired before either half-close")
	default:
	}
	if _, err := client.Write([]byte("still alive")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("still alive"))
	backend.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(backend, buf); err != nil || string(buf) != "still alive" {
		t.Fatalf("ordinary session lost data: %q, %v", buf, err)
	}
	client.CloseWrite()
	backend.CloseWrite()
	relayResult(t, done, false)
}

func TestRelayHalfClosedResponseContinuesWhileMakingProgress(t *testing.T) {
	idle := 200 * time.Millisecond
	client, backend, done := startRelay(t, idle)
	client.CloseWrite()
	backend.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := backend.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("client half-close did not reach backend: %v", err)
	}
	const chunks = 10
	chunk := bytes.Repeat([]byte("response"), 1024)
	writeErr := make(chan error, 1)
	go func() {
		for i := 0; i < chunks; i++ {
			if _, err := backend.Write(chunk); err != nil {
				writeErr <- err
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		writeErr <- backend.CloseWrite()
	}()
	client.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(client)
	if err != nil || !bytes.Equal(got, bytes.Repeat(chunk, chunks)) {
		t.Fatalf("active half-closed response truncated: got %d bytes, %v", len(got), err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	relayResult(t, done, false)
}

func TestRelayBackendResetCancelsOppositeCopy(t *testing.T) {
	client, backend, done := startRelay(t, time.Minute)
	if err := backend.SetLinger(0); err != nil {
		t.Fatal(err)
	}
	backend.Close()
	relayResult(t, done, false)
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("reset backend left client open")
	}
}

func TestHalfCloseIdleConfigurationBounds(t *testing.T) {
	c := defaults()
	c.Node = "test"
	if c.HalfCloseIdleMS != 60000 {
		t.Fatal("unexpected default half-close idle timeout")
	}
	for _, value := range []int{0, 99, 300001} {
		c.HalfCloseIdleMS = value
		if err := validateConfig(c); err == nil {
			t.Fatalf("invalid half-close idle timeout %d accepted", value)
		}
	}
	for _, value := range []int{100, 60000, 300000} {
		c.HalfCloseIdleMS = value
		if err := validateConfig(c); err != nil {
			t.Fatalf("valid half-close idle timeout %d rejected: %v", value, err)
		}
	}
}
