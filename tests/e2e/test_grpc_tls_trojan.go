package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"
)

func testGRPCTLSTrojan() error {
	ctx := context.Background()

	// Start gRPC TLS server
	serverConfig := filepath.Join(projectRoot, "example/example-grpc-tls-server.yaml")
	server, err := startServer(ctx, serverConfig)
	if err != nil {
		return fmt.Errorf("failed to start gRPC TLS server: %w", err)
	}
	defer server.Stop()

	// Wait for server to be ready
	if err := waitForPort(10444, 10*time.Second); err != nil {
		return err
	}

	// Start gRPC TLS client
	clientConfig := filepath.Join(projectRoot, "example/example-grpc-tls-client.yaml")
	client, err := startServer(ctx, clientConfig)
	if err != nil {
		return fmt.Errorf("failed to start gRPC TLS client: %w", err)
	}
	defer client.Stop()

	// Wait for client to be ready
	if err := waitForPort(2082, 10*time.Second); err != nil {
		return err
	}

	// Give services time to stabilize
	time.Sleep(2 * time.Second)

	// Test HTTP proxy through gRPC TLS transport
	if err := testHTTPProxy(2082); err != nil {
		return fmt.Errorf("HTTP proxy test failed: %w", err)
	}

	return nil
}
