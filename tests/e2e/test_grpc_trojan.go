package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"
)

func testGRPCTrojan() error {
	ctx := context.Background()

	// Start gRPC server
	serverConfig := filepath.Join(projectRoot, "example/example-grpc-server.yaml")
	server, err := startServer(ctx, serverConfig)
	if err != nil {
		return fmt.Errorf("failed to start gRPC server: %w", err)
	}
	defer server.Stop()

	// Wait for server to be ready
	if err := waitForPort(10443, 10*time.Second); err != nil {
		return err
	}

	// Start gRPC client
	clientConfig := filepath.Join(projectRoot, "example/example-grpc-client.yaml")
	client, err := startServer(ctx, clientConfig)
	if err != nil {
		return fmt.Errorf("failed to start gRPC client: %w", err)
	}
	defer client.Stop()

	// Wait for client to be ready
	if err := waitForPort(2080, 10*time.Second); err != nil {
		return err
	}

	// Give services time to stabilize
	time.Sleep(2 * time.Second)

	// Test HTTP proxy through gRPC transport
	if err := testHTTPProxy(2080); err != nil {
		return fmt.Errorf("HTTP proxy test failed: %w", err)
	}

	// // Test SOCKS5 proxy through gRPC transport
	// if err := testSOCKS5Proxy(2081); err != nil {
	// 	return fmt.Errorf("SOCKS5 proxy test failed: %w", err)
	// }

	return nil
}
