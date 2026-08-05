package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"time"
)

func testWSTLSTrojan() error {
	log.Println("[ws-tls] ======== START WS+TLS+Trojan ========")
	ctx := context.Background()

	serverConfig := filepath.Join(projectRoot, "tests/e2e/configs/ws-tls-server.yaml")
	log.Printf("[ws-tls] Starting server: %s", serverConfig)
	server, err := startServer(ctx, serverConfig)
	if err != nil {
		return fmt.Errorf("[ws-tls] server start failed: %w", err)
	}
	defer server.Stop()

	log.Println("[ws-tls] Waiting for server port 11001...")
	if err := waitForPort(11001, 10*time.Second); err != nil {
		return fmt.Errorf("[ws-tls] server not ready on 11001: %w", err)
	}
	log.Println("[ws-tls] Server ready on port 11001")

	clientConfig := filepath.Join(projectRoot, "tests/e2e/configs/ws-tls-client.yaml")
	log.Printf("[ws-tls] Starting client: %s", clientConfig)
	client, err := startServer(ctx, clientConfig)
	if err != nil {
		return fmt.Errorf("[ws-tls] client start failed: %w", err)
	}
	defer client.Stop()

	log.Println("[ws-tls] Waiting for client ports 12001 (http), 12002 (socks)...")
	if err := waitForPort(12001, 10*time.Second); err != nil {
		return fmt.Errorf("[ws-tls] client http port 12001 not ready: %w", err)
	}
	if err := waitForPort(12002, 10*time.Second); err != nil {
		return fmt.Errorf("[ws-tls] client socks port 12002 not ready: %w", err)
	}
	log.Println("[ws-tls] Client ready on ports 12001, 12002")

	time.Sleep(2 * time.Second)

	log.Println("[ws-tls] --- HTTP proxy (port 12001) ---")
	if err := testHTTPProxy(12001); err != nil {
		return fmt.Errorf("[ws-tls] HTTP failed: %w", err)
	}
	log.Println("[ws-tls] HTTP PASSED")

	log.Println("[ws-tls] --- SOCKS5 proxy (port 12002) ---")
	if err := testSOCKS5Proxy(12002); err != nil {
		return fmt.Errorf("[ws-tls] SOCKS5 failed: %w", err)
	}
	log.Println("[ws-tls] SOCKS5 PASSED")

	log.Println("[ws-tls] ======== END WS+TLS+Trojan ========")
	return nil
}
