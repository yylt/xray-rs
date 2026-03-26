package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"time"
)

func testTCPTrojan() error {
	ctx := context.Background()

	// Start server
	serverConfig := filepath.Join(projectRoot, "example/example-server.yaml")
	server, err := startServer(ctx, serverConfig)
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	defer server.Stop()

	// Wait for server to be ready
	if err := waitForPort(10443, 10*time.Second); err != nil {
		return err
	}

	// Start client
	clientConfig := filepath.Join(projectRoot, "example/example-client.yaml")
	client, err := startServer(ctx, clientConfig)
	if err != nil {
		return fmt.Errorf("failed to start client: %w", err)
	}
	defer client.Stop()

	// Wait for client to be ready
	if err := waitForPort(2080, 10*time.Second); err != nil {
		return err
	}

	// Give services time to stabilize
	time.Sleep(2 * time.Second)

	// Test HTTP proxy
	if err := testHTTPProxy(2080); err != nil {
		return fmt.Errorf("HTTP proxy test failed: %w", err)
	}

	// Test SOCKS5 proxy
	if err := testSOCKS5Proxy(2081); err != nil {
		return fmt.Errorf("SOCKS5 proxy test failed: %w", err)
	}

	return nil
}

func testHTTPProxy(port int) error {
	log.Printf("Testing HTTP proxy on port %d...", port)

	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		return err
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("http://baidu.com")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if verbose {
		log.Printf("Response: %s", string(body))
	}

	log.Println("✓ HTTP proxy test passed")
	return nil
}

func testSOCKS5Proxy(port int) error {
	log.Printf("Testing SOCKS5 proxy on port %d...", port)

	proxyURL, err := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	if err != nil {
		return err
	}

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("http://baidu.com")
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if verbose {
		log.Printf("Response: %s", string(body))
	}

	log.Println("✓ SOCKS5 proxy test passed")
	return nil
}
