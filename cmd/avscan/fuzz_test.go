package main

import (
	"net"
	"strings"
	"testing"
)

func FuzzParseClamd(f *testing.F) {
	for _, seed := range []string{
		"unix:/run/clamd.sock",
		"tcp:127.0.0.1:3310",
		"tcp:[::1]:3310",
		"",
		"unix",
		"unix:",
		"tcp:",
		"tcp:localhost",
		"http://127.0.0.1:3310",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, addr string) {
		c, err := parseClamd(addr)
		if err != nil {
			if c.Socket != "" || c.Dial != nil {
				t.Fatalf("error with Socket=%q Dial set=%v", c.Socket, c.Dial != nil)
			}
			return
		}
		network, rest, ok := strings.Cut(addr, ":")
		if !ok || rest == "" {
			t.Fatalf("accepted %q", addr)
		}
		switch network {
		case "unix":
			if c.Socket != rest || c.Dial != nil {
				t.Fatalf("unix %q: Socket=%q Dial set=%v", addr, c.Socket, c.Dial != nil)
			}
		case "tcp":
			if _, _, splitErr := net.SplitHostPort(rest); splitErr != nil {
				t.Fatalf("accepted tcp %q", addr)
			}
			if c.Socket != "" || c.Dial == nil {
				t.Fatalf("tcp %q: Socket=%q Dial set=%v", addr, c.Socket, c.Dial != nil)
			}
		default:
			t.Fatalf("accepted %q", addr)
		}
	})
}
