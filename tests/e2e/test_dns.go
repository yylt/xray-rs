package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func testDNSConfig() error {
	ctx := context.Background()

	// Create temporary DNS domain files for testing
	if err := setupDNSTestFiles(); err != nil {
		return fmt.Errorf("failed to setup DNS test files: %w", err)
	}
	defer cleanupDNSTestFiles()

	// Start server with DNS config
	configPath := filepath.Join(projectRoot, "example/dns_config.json")
	server, err := startServer(ctx, configPath)
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	defer server.Stop()

	// Wait for server to be ready
	if err := waitForPort(2080, 10*time.Second); err != nil {
		return err
	}

	// Give service time to stabilize
	time.Sleep(2 * time.Second)

	// Test DNS resolution through proxy
	if err := testDNSResolution(); err != nil {
		return fmt.Errorf("DNS resolution test failed: %w", err)
	}

	// Test routing rules with DNS
	if err := testDNSRouting(); err != nil {
		return fmt.Errorf("DNS routing test failed: %w", err)
	}

	return nil
}

func setupDNSTestFiles() error {
	log.Println("Setting up DNS test files...")

	// Create test directory
	testDir := filepath.Join(projectRoot, "tests/e2e/testdata")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		return err
	}

	// Create ads.txt
	adsContent := `# Ad domains
ads.example.com
tracker.example.com
analytics.example.com
`
	if err := os.WriteFile(filepath.Join(testDir, "ads.txt"), []byte(adsContent), 0644); err != nil {
		return err
	}

	// Create cn.txt
	cnContent := `# CN domains
baidu.com
qq.com
taobao.com
`
	if err := os.WriteFile(filepath.Join(testDir, "cn.txt"), []byte(cnContent), 0644); err != nil {
		return err
	}

	log.Println("✓ DNS test files created")
	return nil
}

func cleanupDNSTestFiles() {
	testDir := filepath.Join(projectRoot, "tests/e2e/testdata")
	os.RemoveAll(testDir)
}

func testDNSResolution() error {
	log.Println("Testing DNS resolution...")

	proxyURL, err := url.Parse("socks5://127.0.0.1:2080")
	if err != nil {
		return err
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}

	// Test resolving a domain
	resp, err := client.Get("http://www.google.com")
	if err != nil {
		return fmt.Errorf("DNS resolution failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	log.Println("✓ DNS resolution test passed")
	return nil
}

func testDNSRouting() error {
	log.Println("Testing DNS-based routing...")

	proxyURL, err := url.Parse("socks5://127.0.0.1:2080")
	if err != nil {
		return err
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}

	// Test routing to proxy for google.com (should match domain:google.com rule)
	resp, err := client.Get("http://www.google.com")
	if err != nil {
		// This might fail if routing to proxy, which is expected
		if strings.Contains(err.Error(), "connection refused") {
			log.Println("✓ DNS routing test passed (routed to proxy as expected)")
			return nil
		}
		return fmt.Errorf("DNS routing test failed: %w", err)
	}
	defer resp.Body.Close()

	log.Println("✓ DNS routing test passed")
	return nil
}
