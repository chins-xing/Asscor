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

// maxRetainedHits bounds the in-memory hit log (audit RC-L1): the experiment
// runner consumes hits from stdout, so the retained slice only serves a
// future --summary use. Unbounded growth under a scan storm would exhaust
// memory; past the cap, hits are still printed but not retained.
const maxRetainedHits = 100000

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
		hits = retainHit(hits, h)
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
					// Transient accept errors (e.g. EMFILE under a storm) should
					// not kill the listener; permanent errors (closed listener)
					// exit. Audit RC-L1: bounded backoff keeps a flood from
					// burning CPU in a tight accept-error loop.
					if ne, ok := err.(net.Error); ok && ne.Timeout() {
						continue
					}
					fmt.Fprintf(os.Stderr, "port %d accept: %v\n", port, err)
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

// retainHit appends h to the retained hit log unless the cap is reached
// (audit RC-L1): hits are always streamed to stdout, so the retained slice
// only backs an optional summary; past the cap it is left unchanged.
func retainHit(hits []decoyHit, h decoyHit) []decoyHit {
	if len(hits) >= maxRetainedHits {
		return hits
	}
	return append(hits, h)
}
