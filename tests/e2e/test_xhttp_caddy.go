package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Only the TLS, hostname-routed Caddy frontend is reachable by the client.
func testXHTTPCaddy(upstream string) error {
	caddy, err := exec.LookPath("caddy")
	if err != nil {
		return fmt.Errorf("XHTTP requires caddy on PATH: %w", err)
	}
	dir, err := os.MkdirTemp("", "xray-xhttp-caddy-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	certFile, keyFile, _, err := writeLocalhostCertificate(dir)
	if err != nil {
		return err
	}
	const backendPort, frontendPort, httpPort = 15001, 15002, 15003
	const password = "xhttp-test-password"
	serverSettings := map[string]any{"path": "/test"}
	endpoint := map[string]any{"port": frontendPort} // Resolve address/SNI/authority from TLS serverName.
	clientSettings := map[string]any{"path": "/test", "upload": endpoint, "download": endpoint}
	serverConfig := map[string]any{
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": backendPort, "protocol": "trojan",
			"settings": map[string]any{"password": password},
			"streamSettings": map[string]any{
				"network": "xhttp", "security": "none",
				"xhttpSettings": serverSettings,
			},
		}},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}},
	}
	clientConfig := map[string]any{
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": httpPort, "protocol": "http",
		}},
		"outbounds": []any{map[string]any{
			"tag": "proxy", "protocol": "trojan",
			"settings": map[string]any{"address": "127.0.0.1", "port": frontendPort, "password": password},
			"streamSettings": map[string]any{
				"network": "xhttp", "security": "tls",
				"tlsSettings":   map[string]any{"serverName": "localhost", "allowInsecure": true, "alpn": []string{"h2"}},
				"xhttpSettings": clientSettings,
			},
		}},
	}
	for _, endpoint := range []struct {
		name   string
		port   int
		config map[string]any
	}{
		{"server", backendPort, serverConfig},
		{"client", httpPort, clientConfig},
	} {
		path, err := writeJSONConfig(dir, endpoint.name, endpoint.config)
		if err != nil {
			return err
		}
		process, err := startServer(context.Background(), path)
		if err != nil {
			return err
		}
		defer process.Stop()
		if err := waitForPort(endpoint.port, 10*time.Second); err != nil {
			return fmt.Errorf("%s not ready: %w", endpoint.name, err)
		}
	}
	// Force the upstream protocol: HTTP/1.1 versus cleartext HTTP/2.
	config := fmt.Sprintf(`{
	admin off
	auto_https off
	skip_install_trust
}
https://localhost:%d {
	tls %s %s
	reverse_proxy 127.0.0.1:%d {
		transport http {
			versions %s
		}
	}
}
`, frontendPort, certFile, keyFile, backendPort, upstream)
	path := filepath.Join(dir, "Caddyfile")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, caddy, "run", "--config", path, "--adapter", "caddyfile")
	// Isolate Caddy autosave and certificate state from the user's directories.
	cmd.Env = append(os.Environ(), "XDG_CONFIG_HOME="+filepath.Join(dir, "config"), "XDG_DATA_HOME="+filepath.Join(dir, "data"))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start caddy: %w", err)
	}
	process := &Process{cmd: cmd, cancel: cancel}
	defer process.Stop()
	if err := waitForPort(frontendPort, 10*time.Second); err != nil {
		return fmt.Errorf("caddy not ready: %w", err)
	}

	payload := bytes.Repeat([]byte("xhttp-caddy-local-echo\n"), 16384)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(len(payload)+1)))
		if err != nil || !bytes.Equal(body, payload) {
			http.Error(w, "upload payload mismatch", http.StatusBadRequest)
			return
		}
		w.Write(payload)
	})
	plain := httptest.NewServer(handler)
	defer plain.Close()
	secure := httptest.NewTLSServer(handler)
	defer secure.Close()
	roots := x509.NewCertPool()
	roots.AddCert(secure.Certificate())
	proxyURL := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", httpPort)}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true,
		TLSClientConfig: secure.Client().Transport.(*http.Transport).TLSClientConfig.Clone(),
	}
	transport.TLSClientConfig.RootCAs = roots
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if err := testXHTTPInteractiveResponse(client); err != nil {
		return fmt.Errorf("interactive response before origin EOF: %w", err)
	}
	for _, target := range []string{plain.URL, secure.URL} {
		resp, err := client.Post(target, "application/octet-stream", bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("%s: %w", target, err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("%s body: %w", target, readErr)
		}
		if resp.StatusCode != http.StatusOK || !bytes.Equal(body, payload) {
			return fmt.Errorf("%s: status=%d, expected %d echo bytes, got %d", target, resp.StatusCode, len(payload), len(body))
		}
		log.Printf("[xhttp caddy %s] PASS %s: %d echo bytes", upstream, target, len(body))
	}
	return nil
}

// The origin cannot finish until the client receives its tiny flushed body.
// It deliberately sends no buffering header: that belongs to the XHTTP layer.
func testXHTTPInteractiveResponse(client *http.Client) error {
	const prefix = "interactive-before-eof\n"
	release := make(chan struct{})
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if _, err := io.WriteString(w, prefix); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer origin.Close()
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin.URL, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data := make([]byte, len(prefix))
	if _, err := io.ReadFull(response.Body, data); err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || string(data) != prefix {
		return fmt.Errorf("status=%d body=%q", response.StatusCode, data)
	}
	return nil
}
