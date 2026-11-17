package main

import (
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
)

// Match complete sshd record forms. Usernames can contain spaces, IP literals,
// and text that resembles another log field, so source extraction must use the
// server-authored terminal address/port tuple rather than searching a message.
var sshRecords = []struct {
	pattern *regexp.Regexp
	failure bool
}{
	{regexp.MustCompile(`^Failed password (?:for|\[redacted\]) (?:invalid user )?.+ from ([0-9a-fA-F:.]+) port ([0-9]+) ssh2(?: \[preauth\])?$`), true},
	{regexp.MustCompile(`^Invalid user .+ from ([0-9a-fA-F:.]+) port ([0-9]+)(?: \[preauth\])?$`), true},
	{regexp.MustCompile(`^Unable to negotiate with ([0-9a-fA-F:.]+) port ([0-9]+): no matching .+$`), true},
	{regexp.MustCompile(`^Bad protocol version identification .+ from ([0-9a-fA-F:.]+) port ([0-9]+)(?: \[preauth\])?$`), true},
	// Closing a connection, including one with an invalid username, is not an
	// additional authentication failure. It can accompany the failure above.
	{regexp.MustCompile(`^(?:Connection (?:closed|reset) by|Disconnected from) (?:(?:invalid user|authenticating user|user) .+ )?([0-9a-fA-F:.]+) port ([0-9]+)(?: \[preauth\])?$`), false},
	{regexp.MustCompile(`^Accepted (?:publickey|password) for .+ from ([0-9a-fA-F:.]+) port ([0-9]+) ssh2(?:[: ].*)?$`), false},
}

func sshSource(unit, message string) (string, bool, bool) {
	if unit != "ssh.service" && unit != "sshd.service" {
		return "", false, false
	}
	for _, record := range sshRecords {
		match := record.pattern.FindStringSubmatch(message)
		if match == nil {
			continue
		}
		ip, err := netip.ParseAddr(match[1])
		port, portErr := strconv.Atoi(match[2])
		if err != nil || ip.Zone() != "" || portErr != nil || port < 1 || port > 65535 {
			return "", false, false
		}
		return ip.Unmap().String(), record.failure, true
	}
	return "", false, false
}

var badPathRX = regexp.MustCompile(`(?i)((?:^|/)\.env(?:$|[/.])|(?:^|/)\.git(?:$|/)|^/(?:wp-login\.php|wp-admin(?:$|/)|actuator(?:$|/)|server-status(?:$|/)|vendor/phpunit(?:$|/)|HNAP1(?:$|/)|boaform(?:$|/)|phpmyadmin(?:$|/)))`)

func sensitivePath(request, uri string) string {
	target := uri
	if fields := strings.Fields(request); len(fields) >= 2 {
		target = fields[1]
	}
	if target == "" || len(target) > 512 {
		return ""
	}
	u, err := url.ParseRequestURI(target)
	if err != nil || u.Path == "" || !strings.HasPrefix(u.Path, "/") {
		return ""
	}
	// ParseRequestURI decodes one escaping layer. Collapse dot segments so
	// aliases of the same path count once and nested sensitive files match.
	canonical := path.Clean(u.Path)
	if !badPathRX.MatchString(canonical) {
		return ""
	}
	return canonical
}

// Keep SYN-only windows in a separate LRU queue. A spray of unauthenticated
// source addresses cannot reserve every slot for six hours or displace existing
// HTTP/SSH evidence before the least-recent SYN window is reclaimed.
func (e *engine) window(ip netip.Addr, transport bool) *bucket {
	b := e.B[ip]
	if b == nil {
		if len(e.B) >= 5000 {
			oldest := e.SYNWindows.Front()
			if oldest == nil {
				if !transport {
					e.Capacity++
					return nil
				}
				oldest = e.TransportWindows.Front()
			}
			if oldest != nil {
				e.dropWindow(oldest.Value.(netip.Addr))
				e.WindowEvictions++
			}
		}
		b = &bucket{Ports: map[int]int64{}, Paths: map[string]int64{}, Fail: map[[32]byte]int64{}}
		e.B[ip] = b
	}
	if transport && !b.Transport {
		if b.Order != nil {
			e.SYNWindows.Remove(b.Order)
		}
		b.Transport = true
		b.Order = nil
	}
	queue := e.SYNWindows
	if b.Transport {
		queue = e.TransportWindows
	}
	if b.Order == nil {
		b.Order = queue.PushBack(ip)
	} else if transport || !b.Transport {
		queue.MoveToBack(b.Order)
	}
	return b
}

func (e *engine) dropWindow(ip netip.Addr) {
	b := e.B[ip]
	if b == nil {
		return
	}
	if b.Transport {
		e.TransportWindows.Remove(b.Order)
	} else if b.Order != nil {
		e.SYNWindows.Remove(b.Order)
	}
	delete(e.B, ip)
	e.Dirty = true
}
