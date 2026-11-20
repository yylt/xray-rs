package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const exampleDomain = "example.com"

// Rust HTTP inbound -> Rust SOCKS5 outbound -> Xray-Core SOCKS5 inbound -> freedom -> example.com
func testHTTPSOCKS5Chain() error {
	dir, err := os.MkdirTemp("", "xray-http-socks-chain-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	const corePort, httpPort = 16001, 16002

	coreConfig := map[string]any{
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": corePort, "protocol": "socks", "tag": "socks-in",
			"settings": map[string]any{"udp": false},
		}},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}},
	}
	clientConfig := map[string]any{
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": httpPort, "protocol": "http", "tag": "http-in",
			"settings": map[string]any{"allowTransparent": false},
		}},
		"outbounds": []any{map[string]any{
			"tag": "proxy", "protocol": "socks",
			"settings": map[string]any{"address": "127.0.0.1", "port": corePort},
		}},
	}

	for _, endpoint := range []struct {
		name, binary string
		config       map[string]any
		ports        []int
	}{
		{"core-socks-server", coreBinary, coreConfig, []int{corePort}},
		{"rust-http-client", binaryPath, clientConfig, []int{httpPort}},
	} {
		path, err := writeJSONConfig(dir, endpoint.name, endpoint.config)
		if err != nil {
			return err
		}
		process, err := startBinary(context.Background(), endpoint.binary, path)
		if err != nil {
			return err
		}
		defer process.Stop()
		for _, port := range endpoint.ports {
			if err := waitForPort(port, 10*time.Second); err != nil {
				return fmt.Errorf("%s not ready: %w", endpoint.name, err)
			}
		}
	}

	return testExampleDomain(httpPort)
}

// 通过 HTTP 代理（Rust inbound）访问公网 example.com，校验响应确实来自目标站点。
func testExampleDomain(port int) error {
	proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("[example.com] invalid proxy URL: %w", err)
	}

	connectOK := false
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		OnProxyConnectResponse: func(_ context.Context, _ *url.URL, _ *http.Request, resp *http.Response) error {
			log.Printf("[example.com CONNECT] Tunnel response: status=%d", resp.StatusCode)
			connectOK = resp.StatusCode == http.StatusOK
			return nil
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}

	for _, tc := range []struct {
		mode, target string
	}{
		{"GET", "http://" + exampleDomain},
		{"CONNECT", "https://" + exampleDomain},
	} {
		log.Printf("[example.com %s] Requesting %s via proxy %s", tc.mode, tc.target, proxyURL)
		start := time.Now()
		resp, err := client.Get(tc.target)
		elapsed := time.Since(start)
		if err != nil {
			return fmt.Errorf("[example.com %s] request failed after %.2fs: %w", tc.mode, elapsed.Seconds(), err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("[example.com %s] read body failed: %w", tc.mode, err)
		}
		log.Printf("[example.com %s] Response: status=%d (%.2fs)", tc.mode, resp.StatusCode, elapsed.Seconds())
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("[example.com %s] unexpected status code: %d", tc.mode, resp.StatusCode)
		}
		if tc.mode == "CONNECT" && !connectOK {
			return fmt.Errorf("[example.com CONNECT] tunnel was not established")
		}
		if !strings.Contains(strings.ToLower(string(body)), "example domain") {
			return fmt.Errorf("[example.com %s] unexpected body: %.100s", tc.mode, string(body))
		}
		log.Printf("[example.com %s] PASS", tc.mode)
	}
	return nil
}
