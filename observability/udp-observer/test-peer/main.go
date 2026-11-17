// Isolated integration fixture. Never installed as a service.
package main

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
	"time"
)

func main() {
	if os.Args[1] == "echo" {
		a, e := net.ResolveUDPAddr("udp", os.Args[2])
		if e != nil {
			panic(e)
		}
		s, e := net.ListenUDP("udp", a)
		if e != nil {
			panic(e)
		}
		defer s.Close()
		b := make([]byte, 2048)
		for {
			n, p, e := s.ReadFromUDP(b)
			if e != nil {
				return
			}
			s.WriteToUDP(b[:n], p)
		}
	}
	l, e := net.ResolveUDPAddr("udp", os.Args[2])
	if e != nil {
		panic(e)
	}
	r, e := net.ResolveUDPAddr("udp", os.Args[3])
	if e != nil {
		panic(e)
	}
	s, e := net.DialUDP("udp", l, r)
	if e != nil {
		panic(e)
	}
	defer s.Close()
	if os.Args[1] == "once" {
		_, e = s.Write([]byte("unsolicited-initial"))
		if e != nil {
			panic(e)
		}
		return
	}
	n, _ := strconv.Atoi(os.Args[4])
	ok := 0
	b := make([]byte, 128)
	for i := 0; i < n; i++ {
		s.SetDeadline(time.Now().Add(time.Second))
		if _, e = s.Write([]byte("fixture-request")); e == nil {
			if _, e = s.Read(b); e == nil {
				ok++
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]int{"sent": n, "replies": ok})
}
