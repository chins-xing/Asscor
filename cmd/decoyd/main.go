//go:build decoyd

// Package main is the decoy daemon deployed inside target containers.
// It listens on the given ports, records any connection, and prints JSON hits
// to stdout (captured by the experiment runner via docker logs or a shared
// volume). Mirrors the ACL honeypot behavior (record-and-close, no response).
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type decoyHit struct {
	Port      int       `json:"port"`
	RemoteIP  string    `json:"remote_ip"`
	Timestamp time.Time `json:"timestamp"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: decoyd <port1,port2,...>")
		os.Exit(1)
	}
	var ports []int
	for _, p := range strings.Split(os.Args[1], ",") {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil {
			ports = append(ports, n)
		}
	}
	var mu sync.Mutex
	var hits []decoyHit
	onHit := func(h decoyHit) {
		mu.Lock()
		hits = append(hits, h)
		mu.Unlock()
		b, _ := json.Marshal(h)
		fmt.Println(string(b))
		os.Stdout.Sync()
	}
	for _, p := range ports {
		go func(port int) {
			ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
			if err != nil {
				fmt.Fprintf(os.Stderr, "port %d: %v\n", port, err)
				return
			}
			fmt.Printf("decoyd listening tcp/%d\n", port)
			os.Stdout.Sync()
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				h := decoyHit{
					Port:      port,
					RemoteIP:  conn.RemoteAddr().(*net.TCPAddr).IP.String(),
					Timestamp: time.Now(),
				}
				conn.Close()
				onHit(h)
			}
		}(p)
	}
	select {} // run forever
}
