package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Test both directions using each implementation's native Trojan settings.
func testCoreCompatibility(network string, coreServer bool) error {
	dir, err := os.MkdirTemp("", "xray-core-compat-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	certFile, keyFile, der, err := writeLocalhostCertificate(dir)
	if err != nil {
		return err
	}
	fingerprint := sha256.Sum256(der)
	const serverPort, httpPort, socksPort = 14001, 14002, 14003
	const password = "compat-test-password"
	streamSettings := func(server, core bool) map[string]any {
		alpn := "http/1.1"
		if network == "grpc" {
			alpn = "h2"
		}
		tls := map[string]any{"serverName": "localhost", "alpn": []string{alpn}}
		if server {
			tls["certificates"] = []any{map[string]any{"certificateFile": certFile, "keyFile": keyFile}}
		} else if core {
			tls["pinnedPeerCertSha256"] = hex.EncodeToString(fingerprint[:])
		} else {
			tls["allowInsecure"] = true
		}
		return map[string]any{
			"network": network, "security": "tls", "tlsSettings": tls,
			"wsSettings":   map[string]any{"path": "/ws"},
			"grpcSettings": map[string]any{"serviceName": "grpc", "multiMode": false},
		}
	}
	serverSettings := map[string]any{"password": password}
	clientSettings := map[string]any{"address": "127.0.0.1", "port": serverPort, "password": password}
	if coreServer {
		serverSettings = map[string]any{"clients": []any{map[string]any{"password": password}}}
	} else {
		clientSettings = map[string]any{"servers": []any{map[string]any{
			"address": "127.0.0.1", "port": serverPort, "password": password,
		}}}
	}
	serverConfig := map[string]any{
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": serverPort, "protocol": "trojan", "tag": "trojan-in",
			"settings": serverSettings, "streamSettings": streamSettings(true, coreServer),
		}},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}},
	}
	clientConfig := map[string]any{
		"inbounds": []any{
			map[string]any{"listen": "127.0.0.1", "port": httpPort, "protocol": "http", "tag": "http-in", "settings": map[string]any{}},
			map[string]any{"listen": "127.0.0.1", "port": socksPort, "protocol": "socks", "tag": "socks-in", "settings": map[string]any{}},
		},
		"outbounds": []any{map[string]any{
			"tag": "proxy", "protocol": "trojan", "settings": clientSettings,
			"streamSettings": streamSettings(false, !coreServer),
		}},
	}
	serverBinary, clientBinary := binaryPath, coreBinary
	if coreServer {
		serverBinary, clientBinary = coreBinary, binaryPath
	}
	for _, endpoint := range []struct {
		name, binary string
		config       map[string]any
		ports        []int
	}{
		{"server", serverBinary, serverConfig, []int{serverPort}},
		{"client", clientBinary, clientConfig, []int{httpPort, socksPort}},
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
	if err := testHTTPProxy(httpPort); err != nil {
		return err
	}
	return testSOCKS5Proxy(socksPort)
}

func writeLocalhostCertificate(dir string) (certFile, keyFile string, der []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", nil, err
	}
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return "", "", nil, err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		return "", "", nil, err
	}
	return certFile, keyFile, der, nil
}

func writeJSONConfig(dir, name string, config map[string]any) (string, error) {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, name+".json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		return "", err
	}
	return path, nil
}
