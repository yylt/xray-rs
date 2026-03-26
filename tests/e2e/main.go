package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

var (
	projectRoot string
	binaryPath  string
	verbose     bool
)

func init() {
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.Parse()

	// Get project root
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	projectRoot = filepath.Join(wd, "../..")
	binaryPath = filepath.Join(projectRoot, "target/release/xray-rs")
}

func main() {
	log.SetFlags(log.Ltime)
	log.Println("Starting E2E tests for xray-rs")

	// Build project first
	if err := buildProject(); err != nil {
		log.Fatalf("Build failed: %v", err)
	}

	// Run test suites
	results := &TestResults{}

	// runTest(results, "TCP + Trojan", testTCPTrojan)
	runTest(results, "gRPC + Trojan", testGRPCTrojan)
	runTest(results, "gRPC TLS + Trojan", testGRPCTLSTrojan)
	// runTest(results, "WebSocket + Trojan", testWebSocketTrojan)
	// runTest(results, "DNS Configuration", testDNSConfig)
	// runTest(results, "Load Balancer", testLoadBalancer)

	// Print summary
	results.PrintSummary()

	if results.Failed > 0 {
		os.Exit(1)
	}
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

	if err := testFunc(); err != nil {
		log.Printf("✗ %s FAILED: %v", name, err)
		results.Failed++
	} else {
		log.Printf("✓ %s PASSED", name)
		results.Passed++
	}
}

func buildProject() error {
	log.Println("Building project...")
	cmd := exec.Command("cargo", "build", "--release")
	cmd.Dir = projectRoot
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	log.Println("✓ Build successful")
	return nil
}

// Process management
type Process struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
}

func startServer(ctx context.Context, configPath string) (*Process, error) {
	ctx, cancel := context.WithCancel(ctx)

	cmd := exec.CommandContext(ctx, binaryPath, "run", "--config", configPath)
	cmd.Dir = projectRoot
	if verbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start server: %w", err)
	}

	return &Process{cmd: cmd, cancel: cancel}, nil
}

func (p *Process) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}
	if p.cmd != nil && p.cmd.Process != nil {
		return p.cmd.Process.Kill()
	}
	return nil
}

func waitForPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			conn.Close()
			log.Printf("Port %d is ready", port)
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timeout waiting for port %d", port)
}
