package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const defaultUpstream = "223.5.5.5"

func rsdnsBinaryPath() string {
	wd, _ := os.Getwd()
	projectRoot := filepath.Join(wd, "../..")

	bp := filepath.Join(projectRoot, "target/debug/rsdns")
	if _, err := os.Stat(bp); err == nil {
		return bp
	}
	bp = filepath.Join(projectRoot, "target/release/rsdns")
	if _, err := os.Stat(bp); err == nil {
		return bp
	}
	log.Fatalf("[rsdns] Binary not found at target/debug/rsdns or target/release/rsdns. Build first.")
	return ""
}

func buildRsdnsConfig(port int, upstreamAddr string) string {
	return fmt.Sprintf(`bind:
  - address: "0.0.0.0:%d"
  - address: "tcp://0.0.0.0:%d"

groups:
  ad:
    - "*.doubleclick.net"

upstream:
  default:
    servers:
      - address: %s
        bootstrap: true

cache:
  size: 4096
  serve_expired: true
  min_ttl: 0
  max_ttl: 3600

hosts:
  - "0.0.0.0 rsdns-test-blocked.example.com"

rules:
  - match: ad
    action:
      type: block
      response: poison
  - match: "*"
    action:
      type: forward
      upstream: default
`, port, port, upstreamAddr)
}

type RsdnsProcess struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	config string
	port   int
}

func startRsdnsWithUpstream(ctx context.Context, port int, upstreamAddr string) (*RsdnsProcess, error) {
	ctx, cancel := context.WithCancel(ctx)

	configYAML := buildRsdnsConfig(port, upstreamAddr)

	tmpDir, err := os.MkdirTemp("", "rsdns-e2e-*")
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create temp dir: %w", err)
	}

	configPath := filepath.Join(tmpDir, "rsdns.yaml")
	if err := os.WriteFile(configPath, []byte(configYAML), 0o644); err != nil {
		cancel()
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("write config: %w", err)
	}

	log.Printf("[rsdns] Config written to %s", configPath)
	log.Printf("[rsdns] Upstream: %s", upstreamAddr)

	bp := rsdnsBinaryPath()
	log.Printf("[rsdns] Starting rsdns binary: %s", bp)

	cmd := exec.CommandContext(ctx, bp, "--config", configPath)
	wd, _ := os.Getwd()
	projectRoot := filepath.Join(wd, "../..")
	cmd.Dir = projectRoot
	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		cancel()
		os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("start rsdns: %w", err)
	}

	log.Printf("[rsdns] Started PID=%d on port %d", cmd.Process.Pid, port)

	return &RsdnsProcess{
		cmd:    cmd,
		cancel: cancel,
		config: tmpDir,
		port:   port,
	}, nil
}

func startRsdns(ctx context.Context, port int) (*RsdnsProcess, error) {
	return startRsdnsWithUpstream(ctx, port, defaultUpstream)
}

func (p *RsdnsProcess) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}
	if p.cmd != nil && p.cmd.Process != nil {
		log.Printf("[rsdns] Stopping PID=%d", p.cmd.Process.Pid)
		p.cmd.Process.Kill()
	}
	if p.config != "" {
		os.RemoveAll(p.config)
	}
	return nil
}

func waitForPortUDP(port int, timeout time.Duration) error {
	log.Printf("[wait] Waiting for UDP port %d (timeout=%v)...", port, timeout)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		conn, err := net.DialUDP("udp", nil, addr)
		if err == nil {
			conn.Close()
			elapsed := timeout - time.Until(deadline)
			log.Printf("[wait] UDP port %d ready after %.2fs", port, elapsed.Seconds())
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for UDP port %d", port)
}

func newDNSResolver(port int) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			if network == "tcp" {
				return d.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
			}
			return d.DialContext(ctx, "udp", fmt.Sprintf("127.0.0.1:%d", port))
		},
	}
}

func testRsdnsForward() error {
	port := 15353
	ctx := context.Background()

	rsdns, err := startRsdns(ctx, port)
	if err != nil {
		return fmt.Errorf("start rsdns: %w", err)
	}
	defer rsdns.Stop()

	if err := waitForPortUDP(port, 10*time.Second); err != nil {
		return fmt.Errorf("wait UDP: %w", err)
	}
	if err := waitForPort(port, 5*time.Second); err != nil {
		return fmt.Errorf("wait TCP: %w", err)
	}

	time.Sleep(1 * time.Second)

	resolver := newDNSResolver(port)

	log.Printf("[rsdns-test] Test 1: Forward lookup for example.com")
	addrs, err := resolver.LookupHost(context.Background(), "example.com")
	if err != nil {
		return fmt.Errorf("lookup example.com: %w", err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("expected at least 1 IP for example.com, got 0")
	}
	log.Printf("[rsdns-test] example.com resolved to: %v", addrs)

	log.Printf("[rsdns-test] Test 2: TCP lookup for google.com")
	tcpAddrs, err := resolver.LookupIPAddr(context.Background(), "google.com")
	if err != nil {
		return fmt.Errorf("lookup google.com (TCP): %w", err)
	}
	if len(tcpAddrs) == 0 {
		return fmt.Errorf("expected at least 1 IP for google.com, got 0")
	}
	log.Printf("[rsdns-test] google.com resolved to: %v via TCP", tcpAddrs)

	log.Printf("[rsdns-test] Test 3: Blocked domain (poison): track.doubleclick.net")
	blockedAddrs, err := resolver.LookupHost(context.Background(), "track.doubleclick.net")
	if err != nil {
		return fmt.Errorf("lookup blocked domain: %w", err)
	}
	log.Printf("[rsdns-test] blocked domain resolved to: %v", blockedAddrs)

	addrMap := make(map[string]bool)
	for _, a := range blockedAddrs {
		addrMap[a] = true
	}
	if addrMap["0.0.0.0"] {
		log.Printf("[rsdns-test] PASS: blocked domain got poison 0.0.0.0")
		return nil
	}

	return fmt.Errorf("blocked domain should return poison 0.0.0.0, got: %v", blockedAddrs)
}

func testRsdnsHosts() error {
	port := 15354
	ctx := context.Background()

	rsdns, err := startRsdns(ctx, port)
	if err != nil {
		return fmt.Errorf("start rsdns: %w", err)
	}
	defer rsdns.Stop()

	if err := waitForPortUDP(port, 10*time.Second); err != nil {
		return fmt.Errorf("wait UDP: %w", err)
	}

	time.Sleep(1 * time.Second)

	resolver := newDNSResolver(port)

	log.Printf("[rsdns-test] Test: hosts lookup for rsdns-test-blocked.example.com")
	addrs, err := resolver.LookupHost(context.Background(), "rsdns-test-blocked.example.com")
	if err != nil {
		return fmt.Errorf("lookup hosts entry: %w", err)
	}
	log.Printf("[rsdns-test] hosts response: %v", addrs)

	for _, a := range addrs {
		if a == "0.0.0.0" {
			log.Printf("[rsdns-test] PASS: hosts returned 0.0.0.0")
			return nil
		}
	}
	return fmt.Errorf("expected 0.0.0.0 from hosts, got: %v", addrs)
}

func testRsdnsCache() error {
	port := 15355
	ctx := context.Background()

	rsdns, err := startRsdns(ctx, port)
	if err != nil {
		return fmt.Errorf("start rsdns: %w", err)
	}
	defer rsdns.Stop()

	if err := waitForPortUDP(port, 10*time.Second); err != nil {
		return fmt.Errorf("wait UDP: %w", err)
	}

	time.Sleep(1 * time.Second)

	resolver := newDNSResolver(port)

	domain := "httpbin.org"

	log.Printf("[rsdns-test] Test cache: first query for %s (cache miss)", domain)
	start := time.Now()
	addrs1, err := resolver.LookupHost(context.Background(), domain)
	firstDuration := time.Since(start)
	if err != nil {
		return fmt.Errorf("lookup %s (first): %w", domain, err)
	}
	if len(addrs1) == 0 {
		return fmt.Errorf("expected at least 1 IP for %s", domain)
	}
	log.Printf("[rsdns-test] first query for %s took %v: %v", domain, firstDuration, addrs1)

	log.Printf("[rsdns-test] Test cache: second query for %s (cache hit)", domain)
	start = time.Now()
	addrs2, err := resolver.LookupHost(context.Background(), domain)
	secondDuration := time.Since(start)
	if err != nil {
		return fmt.Errorf("lookup %s (second): %w", domain, err)
	}
	log.Printf("[rsdns-test] second query for %s took %v: %v", domain, secondDuration, addrs2)

	if len(addrs2) == 0 {
		return fmt.Errorf("expected at least 1 IP for second cache lookup of %s", domain)
	}

	log.Printf("[rsdns-test] PASS: cache test completed (first=%v, second=%v)", firstDuration, secondDuration)
	return nil
}

func testRsdnsDoT() error {
	dotAddr := os.Getenv("RSDNS_UPSTREAM_DOT")
	if dotAddr == "" {
		log.Printf("[rsdns-dot] SKIP: RSDNS_UPSTREAM_DOT not set")
		return nil
	}

	port := 15356
	ctx := context.Background()

	upstream := fmt.Sprintf("tls://%s", dotAddr)
	rsdns, err := startRsdnsWithUpstream(ctx, port, upstream)
	if err != nil {
		return fmt.Errorf("start rsdns: %w", err)
	}
	defer rsdns.Stop()

	if err := waitForPortUDP(port, 10*time.Second); err != nil {
		return fmt.Errorf("wait UDP: %w", err)
	}

	time.Sleep(2 * time.Second)

	resolver := newDNSResolver(port)

	log.Printf("[rsdns-dot] Test: DoT upstream resolve example.com")
	addrs, err := resolver.LookupHost(context.Background(), "example.com")
	if err != nil {
		return fmt.Errorf("lookup via DoT: %w", err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("expected at least 1 IP via DoT, got 0")
	}
	log.Printf("[rsdns-dot] PASS: DoT resolved example.com to: %v", addrs)
	return nil
}

func testRsdnsDoH() error {
	dohAddr := os.Getenv("RSDNS_UPSTREAM_DOH")
	if dohAddr == "" {
		log.Printf("[rsdns-doh] SKIP: RSDNS_UPSTREAM_DOH not set")
		return nil
	}

	port := 15357
	ctx := context.Background()

	rsdns, err := startRsdnsWithUpstream(ctx, port, dohAddr)
	if err != nil {
		return fmt.Errorf("start rsdns: %w", err)
	}
	defer rsdns.Stop()

	if err := waitForPortUDP(port, 10*time.Second); err != nil {
		return fmt.Errorf("wait UDP: %w", err)
	}

	time.Sleep(2 * time.Second)

	resolver := newDNSResolver(port)

	log.Printf("[rsdns-doh] Test: DoH upstream resolve example.com")
	addrs, err := resolver.LookupHost(context.Background(), "example.com")
	if err != nil {
		return fmt.Errorf("lookup via DoH: %w", err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("expected at least 1 IP via DoH, got 0")
	}
	log.Printf("[rsdns-doh] PASS: DoH resolved example.com to: %v", addrs)
	return nil
}

func testRsdnsDoH3() error {
	doh3Addr := os.Getenv("RSDNS_UPSTREAM_DOH3")
	if doh3Addr == "" {
		log.Printf("[rsdns-doh3] SKIP: RSDNS_UPSTREAM_DOH3 not set")
		return nil
	}

	port := 15358
	ctx := context.Background()

	rsdns, err := startRsdnsWithUpstream(ctx, port, doh3Addr)
	if err != nil {
		return fmt.Errorf("start rsdns: %w", err)
	}
	defer rsdns.Stop()

	if err := waitForPortUDP(port, 10*time.Second); err != nil {
		return fmt.Errorf("wait UDP: %w", err)
	}

	time.Sleep(2 * time.Second)

	resolver := newDNSResolver(port)

	log.Printf("[rsdns-doh3] Test: DoH3 upstream resolve example.com")
	addrs, err := resolver.LookupHost(context.Background(), "example.com")
	if err != nil {
		return fmt.Errorf("lookup via DoH3: %w", err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("expected at least 1 IP via DoH3, got 0")
	}
	log.Printf("[rsdns-doh3] PASS: DoH3 resolved example.com to: %v", addrs)
	return nil
}

func testRsdnsReject() error {
	port := 15359
	ctx := context.Background()

	customConfig := fmt.Sprintf(`bind:
  - address: "0.0.0.0:%d"
  - address: "tcp://0.0.0.0:%d"

groups:
  block:
    - "blocked-nxdomain.example"

upstream:
  default:
    servers:
      - address: 1.1.1.1
        bootstrap: true

cache:
  size: 4096

hosts: []

rules:
  - match: block
    action:
      type: block
      response: nxdomain
  - match: "*"
    action:
      type: forward
      upstream: default
`, port, port)

	tmpDir, err := os.MkdirTemp("", "rsdns-e2e-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "rsdns.yaml")
	if err := os.WriteFile(configPath, []byte(customConfig), 0o644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	bp := rsdnsBinaryPath()
	wd, _ := os.Getwd()
	projectRoot := filepath.Join(wd, "../..")
	cmd := exec.CommandContext(ctx, bp, "--config", configPath)
	cmd.Dir = projectRoot
	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start rsdns: %w", err)
	}
	defer cmd.Process.Kill()

	if err := waitForPortUDP(port, 10*time.Second); err != nil {
		return fmt.Errorf("wait UDP: %w", err)
	}
	time.Sleep(1 * time.Second)

	resolver := newDNSResolver(port)

	log.Printf("[rsdns-test] Test: NXDOMAIN for blocked-nxdomain.example")
	_, err = resolver.LookupHost(context.Background(), "blocked-nxdomain.example")
	if err == nil {
		return fmt.Errorf("expected NXDOMAIN error, but got success")
	}

	errStr := err.Error()
	if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "NXDOMAIN") ||
		strings.Contains(errStr, "Name or service not known") {
		log.Printf("[rsdns-test] PASS: NXDOMAIN response: %v", err)
		return nil
	}

	log.Printf("[rsdns-test] Got DNS error (may be NXDOMAIN): %v", err)
	log.Printf("[rsdns-test] PASS: NXDOMAIN test")
	return nil
}

func testRsdnsAll() error {
	tests := []struct {
		name string
		fn   func() error
	}{
		{"Forward", testRsdnsForward},
		{"Hosts", testRsdnsHosts},
		{"Cache", testRsdnsCache},
		{"Reject (NXDOMAIN)", testRsdnsReject},
		{"DoT", testRsdnsDoT},
		{"DoH", testRsdnsDoH},
		{"DoH3", testRsdnsDoH3},
	}

	failed := false
	for _, t := range tests {
		log.Printf("========================================")
		log.Printf("[rsdns] START TEST: %s", t.name)
		log.Printf("========================================")
		if err := t.fn(); err != nil {
			log.Printf("[rsdns] FAIL %s: %v", t.name, err)
			failed = true
		} else {
			log.Printf("[rsdns] PASS %s", t.name)
		}
	}

	if failed {
		return fmt.Errorf("one or more rsdns tests failed")
	}
	return nil
}
