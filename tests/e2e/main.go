package main

import (
	"context"
	"errors"
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
	coreBinary  string
)

// errSkip is a sentinel error that signals a test was skipped.
var errSkip = errors.New("SKIP")

func init() {
	flag.StringVar(&coreBinary, "core", "", "Xray-Core binary for bidirectional compatibility tests")
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.Parse()

	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	projectRoot = filepath.Join(wd, "../..")
}

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Printf("[main] Starting E2E tests suite=xray")
	log.Printf("[main] projectRoot=%s binaryPath=%s verbose=%v", projectRoot, binaryPath, verbose)

	binaryPath = filepath.Join(projectRoot, "target/debug/xray-rs")
	if _, err := os.Stat(binaryPath); err != nil {
		log.Printf("[main] Debug binary not found, trying release...")
		binaryPath = filepath.Join(projectRoot, "target/release/xray-rs")
		if _, err := os.Stat(binaryPath); err != nil {
			log.Fatalf("[main] Binary not found at %s. Build first.", binaryPath)
		}
	}
	log.Printf("[main] Using binary: %s", binaryPath)

	results := &TestResults{}

	runTest(results, "WebSocket+TLS+Trojan", testWSTLSTrojan)
	runTest(results, "gRPC+TLS+Trojan", testGRPCTLSTrojan)
	if coreBinary != "" {
		resolved, err := exec.LookPath(coreBinary)
		if err != nil {
			log.Fatalf("[main] Xray-Core binary: %v", err)
		}
		coreBinary, err = filepath.Abs(resolved)
		if err != nil {
			log.Fatal(err)
		}
		for _, network := range []string{"ws", "grpc"} {
			for _, coreServer := range []bool{false, true} {
				direction := "Core client -> Rust server"
				if coreServer {
					direction = "Rust client -> Core server"
				}
				runTest(results, network+"+TLS+Trojan: "+direction, func() error {
					return testCoreCompatibility(network, coreServer)
				})
			}
		}
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
	err := testFunc()
	elapsed := time.Since(start)

	if errors.Is(err, errSkip) {
		log.Printf("[run] SKIP %s (%.2fs)", name, elapsed.Seconds())
		results.Skipped++
	} else if err != nil {
		log.Printf("[run] FAIL %s (%.2fs): %v", name, elapsed.Seconds(), err)
		results.Failed++
	} else {
		log.Printf("[run] PASS %s (%.2fs)", name, elapsed.Seconds())
		results.Passed++
	}
}

type Process struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
}

func startServer(ctx context.Context, configPath string) (*Process, error) {
	return startBinary(ctx, binaryPath, configPath)
}

func startBinary(ctx context.Context, binary, configPath string) (*Process, error) {
	ctx, cancel := context.WithCancel(ctx)

	log.Printf("[proc] Starting %s with config: %s", binary, configPath)
	cmd := exec.CommandContext(ctx, binary, "run", "--config", configPath)
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
		_ = p.cmd.Process.Kill()
		return p.cmd.Wait()
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
	for _, tc := range []struct {
		mode string
		url  string
	}{
		{"GET", "http://baidu.com"},
		{"CONNECT", "https://www.baidu.com"},
	} {
		if err := testHTTPProxyRequest(port, tc.mode, tc.url); err != nil {
			return fmt.Errorf("[http-proxy %s] %w", tc.mode, err)
		}
	}
	return nil
}

func testHTTPProxyRequest(port int, mode, targetURL string) error {
	log.Printf("[http-proxy %s] Testing HTTP proxy on port %d...", mode, port)

	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("[http-proxy] invalid proxy URL: %w", err)
	}

	connectOK := false
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		OnProxyConnectResponse: func(_ context.Context, _ *url.URL, _ *http.Request, resp *http.Response) error {
			log.Printf("[http-proxy CONNECT] Tunnel response: status=%d", resp.StatusCode)
			connectOK = resp.StatusCode == http.StatusOK
			return nil
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		// Keep plain HTTP GET independent of HTTPS redirects (which use CONNECT).
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	log.Printf("[http-proxy %s] Requesting %s via proxy %s", mode, targetURL, proxyURL)
	start := time.Now()
	resp, err := client.Get(targetURL)
	elapsed := time.Since(start)
	if err != nil {
		return fmt.Errorf("[http-proxy] request failed after %.2fs: %w", elapsed.Seconds(), err)
	}
	defer resp.Body.Close()

	log.Printf("[http-proxy %s] Response: status=%d (%.2fs)", mode, resp.StatusCode, elapsed.Seconds())

	if mode == "CONNECT" && !connectOK {
		return fmt.Errorf("CONNECT tunnel was not established")
	}
	// baidu.com redirects plain HTTP to HTTPS; do not follow it in the GET case.
	redirect := resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound ||
		resp.StatusCode == http.StatusTemporaryRedirect || resp.StatusCode == http.StatusPermanentRedirect
	if resp.StatusCode != http.StatusOK && !(mode == "GET" && redirect && resp.Header.Get("Location") != "") {
		return fmt.Errorf("[http-proxy] unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return fmt.Errorf("[http-proxy] read body failed: %w", err)
	}
	if len(body) == 0 {
		return fmt.Errorf("[http-proxy] empty response body")
	}
	log.Printf("[http-proxy %s] Body preview (%d bytes): %.100s", mode, len(body), string(body))
	log.Printf("[http-proxy %s] PASS", mode)
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
