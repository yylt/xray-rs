package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"time"
)

func testLoadBalancer() error {
	ctx := context.Background()

	// Start gRPC server (for load balancer to connect to)
	serverConfig := filepath.Join(projectRoot, "example/example-grpc-server.yaml")
	server, err := startServer(ctx, serverConfig)
	if err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}
	defer server.Stop()

	// Wait for server to be ready
	if err := waitForPort(10443, 10*time.Second); err != nil {
		return err
	}

	// Start load balancer client
	lbConfig := filepath.Join(projectRoot, "example/example-lb-client.yaml")
	client, err := startServer(ctx, lbConfig)
	if err != nil {
		return fmt.Errorf("failed to start load balancer client: %w", err)
	}
	defer client.Stop()

	// Wait for client to be ready
	if err := waitForPort(2080, 10*time.Second); err != nil {
		return err
	}

	// Give services time to stabilize
	time.Sleep(2 * time.Second)

	// Test multiple requests to verify load balancing
	log.Println("Testing load balancer with multiple requests...")
	for i := 0; i < 5; i++ {
		if err := testHTTPProxy(2080); err != nil {
			return fmt.Errorf("load balancer request %d failed: %w", i+1, err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	log.Println("✓ Load balancer test passed")
	return nil
}
