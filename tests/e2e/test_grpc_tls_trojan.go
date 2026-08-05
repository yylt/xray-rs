package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"time"
)

func testGRPCTLSTrojan() error {
	log.Println("[grpc-tls] ======== START gRPC+TLS+Trojan ========")
	ctx := context.Background()

	serverConfig := filepath.Join(projectRoot, "tests/e2e/configs/grpc-tls-server.yaml")
	log.Printf("[grpc-tls] Starting server: %s", serverConfig)
	server, err := startServer(ctx, serverConfig)
	if err != nil {
		return fmt.Errorf("[grpc-tls] server start failed: %w", err)
	}
	defer server.Stop()

	log.Println("[grpc-tls] Waiting for server port 11002...")
	if err := waitForPort(11002, 10*time.Second); err != nil {
		return fmt.Errorf("[grpc-tls] server not ready on 11002: %w", err)
	}
	log.Println("[grpc-tls] Server ready on port 11002")

	clientConfig := filepath.Join(projectRoot, "tests/e2e/configs/grpc-tls-client.yaml")
	log.Printf("[grpc-tls] Starting client: %s", clientConfig)
	client, err := startServer(ctx, clientConfig)
	if err != nil {
		return fmt.Errorf("[grpc-tls] client start failed: %w", err)
	}
	defer client.Stop()

	log.Println("[grpc-tls] Waiting for client ports 13001 (http), 13002 (socks)...")
	if err := waitForPort(13001, 10*time.Second); err != nil {
		return fmt.Errorf("[grpc-tls] client http port 13001 not ready: %w", err)
	}
	if err := waitForPort(13002, 10*time.Second); err != nil {
		return fmt.Errorf("[grpc-tls] client socks port 13002 not ready: %w", err)
	}
	log.Println("[grpc-tls] Client ready on ports 13001, 13002")

	time.Sleep(2 * time.Second)

	log.Println("[grpc-tls] --- HTTP proxy (port 13001) ---")
	if err := testHTTPProxy(13001); err != nil {
		return fmt.Errorf("[grpc-tls] HTTP failed: %w", err)
	}
	log.Println("[grpc-tls] HTTP PASSED")

	log.Println("[grpc-tls] --- SOCKS5 proxy (port 13002) ---")
	if err := testSOCKS5Proxy(13002); err != nil {
		return fmt.Errorf("[grpc-tls] SOCKS5 failed: %w", err)
	}
	log.Println("[grpc-tls] SOCKS5 PASSED")

	log.Println("[grpc-tls] ======== END gRPC+TLS+Trojan ========")
	return nil
}
