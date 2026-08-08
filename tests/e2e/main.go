package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

var (
	projectRoot string
	binaryPath  string
	verbose     bool
	suite       string
)

func init() {
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.StringVar(&suite, "suite", "all", "test suite: xray, rsdns, all")
	flag.Parse()

	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	projectRoot = filepath.Join(wd, "../..")

	if suite == "rsdns" {
		binaryPath = filepath.Join(projectRoot, "target/debug/rsdns")
	} else {
		binaryPath = filepath.Join(projectRoot, "target/debug/xray-rs")
	}
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Printf("[main] Starting E2E tests suite=%s", suite)
	log.Printf("[main] projectRoot=%s binaryPath=%s verbose=%v", projectRoot, binaryPath, verbose)

	if suite == "rsdns" {
		rsdnsBin := filepath.Join(projectRoot, "target/debug/rsdns")
		if _, err := os.Stat(rsdnsBin); err != nil {
			rsdnsBin = filepath.Join(projectRoot, "target/release/rsdns")
			if _, err := os.Stat(rsdnsBin); err != nil {
				log.Fatalf("[main] rsdns binary not found at target/debug/rsdns or target/release/rsdns. Build first.")
			}
		}
		binaryPath = rsdnsBin
		log.Printf("[main] Using rsdns binary: %s", binaryPath)
	} else {
		if _, err := os.Stat(binaryPath); err != nil {
			log.Printf("[main] Debug binary not found, trying release...")
			binaryPath = filepath.Join(projectRoot, "target/release/xray-rs")
			if _, err := os.Stat(binaryPath); err != nil {
				log.Fatalf("[main] Binary not found at %s. Build first.", binaryPath)
			}
		}
		log.Printf("[main] Using binary: %s", binaryPath)
	}

	results := &TestResults{}

	if suite == "all" || suite == "xray" {
		runTest(results, "WebSocket+TLS+Trojan", testWSTLSTrojan)
		runTest(results, "gRPC+TLS+Trojan", testGRPCTLSTrojan)
	}

	if suite == "all" || suite == "rsdns" {
		runTest(results, "rsdns", testRsdnsAll)
	}

	results.PrintSummary()

	if results.Failed > 0 {
		os.Exit(1)
	}
	log.Println("[main] All tests passed")
}

type TestResults struct {
	Passed  int
	Failed  int
	Skipped int
}

func (r *TestResults) PrintSummary() {
	fmt.Println("\n========================================")
	fmt.Println("TEST SUMMARY")
	fmt.Println("========================================")
	fmt.Printf("Passed:  %d\n", r.Passed)
	fmt.Printf("Failed:  %d\n", r.Failed)
	fmt.Printf("Skipped: %d\n", r.Skipped)
	fmt.Println("========================================")
}

func runTest(results *TestResults, name string, testFunc func() error) {
	fmt.Printf("\n========================================\n")
	fmt.Printf("TEST: %s\n", name)
	fmt.Printf("========================================\n")
	log.Printf("[run] START %s", name)

	start := time.Now()
	if err := testFunc(); err != nil {
		elapsed := time.Since(start)
		log.Printf("[run] FAIL %s (%.2fs): %v", name, elapsed.Seconds(), err)
		results.Failed++
	} else {
		elapsed := time.Since(start)
		log.Printf("[run] PASS %s (%.2fs)", name, elapsed.Seconds())
		results.Passed++
	}
}

type Process struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
}

func startServer(ctx context.Context, configPath string) (*Process, error) {
	ctx, cancel := context.WithCancel(ctx)

	log.Printf("[proc] Starting xray-rs with config: %s", configPath)
	cmd := exec.CommandContext(ctx, binaryPath, "run", "--config", configPath)
	cmd.Dir = projectRoot
	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		cancel()
		log.Printf("[proc] FAILED to start: %v", err)
		return nil, fmt.Errorf("failed to start server: %w", err)
	}

	log.Printf("[proc] Started PID=%d config=%s", cmd.Process.Pid, filepath.Base(configPath))
	return &Process{cmd: cmd, cancel: cancel}, nil
}

func (p *Process) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}
	if p.cmd != nil && p.cmd.Process != nil {
		log.Printf("[proc] Stopping PID=%d", p.cmd.Process.Pid)
		return p.cmd.Process.Kill()
	}
	return nil
}

func waitForPort(port int, timeout time.Duration) error {
	log.Printf("[wait] Waiting for port %d (timeout=%v)...", port, timeout)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			conn.Close()
			elapsed := timeout - time.Until(deadline)
			log.Printf("[wait] Port %d ready after %.2fs", port, elapsed.Seconds())
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for port %d", port)
}

func testHTTPProxy(port int) error {
	log.Printf("[http-proxy] Testing HTTP proxy on port %d...", port)

	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("[http-proxy] invalid proxy URL: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 15 * time.Second,
	}

	log.Printf("[http-proxy] Requesting http://baidu.com via proxy %s", proxyURL)
	start := time.Now()
	resp, err := client.Get("http://baidu.com")
	elapsed := time.Since(start)
	if err != nil {
		return fmt.Errorf("[http-proxy] request failed after %.2fs: %w", elapsed.Seconds(), err)
	}
	defer resp.Body.Close()

	log.Printf("[http-proxy] Response: status=%d (%.2fs)", resp.StatusCode, elapsed.Seconds())

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("[http-proxy] unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return fmt.Errorf("[http-proxy] read body failed: %w", err)
	}
	log.Printf("[http-proxy] Body preview (%d bytes): %.100s", len(body), string(body))
	log.Printf("[http-proxy] PASS")
	return nil
}

func testSOCKS5Proxy(port int) error {
	log.Printf("[socks5] Testing SOCKS5 proxy on port %d...", port)

	proxyURL, err := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("[socks5] invalid proxy URL: %w", err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 15 * time.Second,
	}

	log.Printf("[socks5] Requesting http://baidu.com via proxy %s", proxyURL)
	start := time.Now()
	resp, err := client.Get("http://baidu.com")
	elapsed := time.Since(start)
	if err != nil {
		return fmt.Errorf("[socks5] request failed after %.2fs: %w", elapsed.Seconds(), err)
	}
	defer resp.Body.Close()

	log.Printf("[socks5] Response: status=%d (%.2fs)", resp.StatusCode, elapsed.Seconds())

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("[socks5] unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return fmt.Errorf("[socks5] read body failed: %w", err)
	}
	log.Printf("[socks5] Body preview (%d bytes): %.100s", len(body), string(body))
	log.Printf("[socks5] PASS")
	return nil
}

func testFreedom(targetURL string) error {
	log.Printf("[freedom] Testing freedom outbound at %s...", targetURL)

	u, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("[freedom] invalid URL: %w", err)
	}
	log.Printf("[freedom] Target: %s (host=%s port=%s)", targetURL, u.Hostname(), u.Port())

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	start := time.Now()
	resp, err := client.Get(targetURL)
	elapsed := time.Since(start)
	if err != nil {
		return fmt.Errorf("[freedom] request failed after %.2fs: %w", elapsed.Seconds(), err)
	}
	defer resp.Body.Close()

	log.Printf("[freedom] Response: status=%d (%.2fs)", resp.StatusCode, elapsed.Seconds())

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return fmt.Errorf("[freedom] read body failed: %w", err)
	}
	log.Printf("[freedom] Body preview (%d bytes): %.100s", len(body), string(body))
	log.Printf("[freedom] PASS")
	return nil
}
