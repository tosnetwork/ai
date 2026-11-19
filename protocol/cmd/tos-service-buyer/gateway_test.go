package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/gen/tos/service/v1/tosservicev1connect"
)

func withGateway(c map[string]any) {
	c["gateway_url"] = "https://gateway.example"
	c["gateway_ca_file"] = "/srv/buyer/gateway-ca.pem"
	c["gateway_token_file"] = "/srv/buyer/gateway-token"
}

func TestTheGatewayAndCatalogConfigurationIsValidated(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"an https gateway": withGateway,
		"a loopback http gateway": func(c map[string]any) {
			c["gateway_url"], c["gateway_token_file"] = "http://127.0.0.1:8080", "/srv/buyer/gateway-token"
		},
		"a localhost http gateway": func(c map[string]any) {
			c["gateway_url"], c["gateway_token_file"] = "http://localhost:8080", "/srv/buyer/gateway-token"
		},
		"a catalog": func(c map[string]any) { c["catalog_dir"] = "/srv/buyer/catalog" },
	} {
		value := validAgentConfig()
		edit(value)
		if _, err := readAgentConfig(writeAgentConfig(t, value, 0o600)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, edit := range map[string]func(map[string]any){
		"an http gateway off loopback": func(c map[string]any) {
			withGateway(c)
			c["gateway_url"] = "http://gateway.example"
			delete(c, "gateway_ca_file")
		},
		"an https gateway without a CA": func(c map[string]any) { withGateway(c); delete(c, "gateway_ca_file") },
		"a CA for a plaintext gateway":  func(c map[string]any) { withGateway(c); c["gateway_url"] = "http://127.0.0.1:8080" },
		"no token file":                 func(c map[string]any) { withGateway(c); delete(c, "gateway_token_file") },
		"a relative token file":         func(c map[string]any) { withGateway(c); c["gateway_token_file"] = "token" },
		"a relative CA file":            func(c map[string]any) { withGateway(c); c["gateway_ca_file"] = "ca.pem" },
		"a token without a gateway":     func(c map[string]any) { c["gateway_token_file"] = "/srv/buyer/gateway-token" },
		"a CA without a gateway":        func(c map[string]any) { c["gateway_ca_file"] = "/srv/buyer/gateway-ca.pem" },
		"a gateway path":                func(c map[string]any) { withGateway(c); c["gateway_url"] = "https://gateway.example/api" },
		"a gateway query":               func(c map[string]any) { withGateway(c); c["gateway_url"] = "https://gateway.example?x=1" },
		"a gateway fragment":            func(c map[string]any) { withGateway(c); c["gateway_url"] = "https://gateway.example#x" },
		"gateway credentials":           func(c map[string]any) { withGateway(c); c["gateway_url"] = "https://u:p@gateway.example" },
		"another scheme":                func(c map[string]any) { withGateway(c); c["gateway_url"] = "ftp://gateway.example" },
		"no host":                       func(c map[string]any) { withGateway(c); c["gateway_url"] = "https:///" },
		"an unclean URL":                func(c map[string]any) { withGateway(c); c["gateway_url"] = "HTTPS://gateway.example" },
		"a relative catalog":            func(c map[string]any) { c["catalog_dir"] = "catalog" },
	} {
		value := validAgentConfig()
		edit(value)
		if _, err := readAgentConfig(writeAgentConfig(t, value, 0o600)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func writeToken(t *testing.T, dir, token string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTheGatewayTokenIsOneOwnerPrivateToken(t *testing.T) {
	dir := t.TempDir()
	if token, err := readGatewayToken(writeToken(t, dir, "s3cret-token\n", 0o600)); err != nil || token != "s3cret-token" {
		t.Fatalf("a valid token: %q %v", token, err)
	}
	for name, file := range map[string]func() string{
		"readable by the group": func() string { return writeToken(t, t.TempDir(), "token", 0o640) },
		"empty":                 func() string { return writeToken(t, t.TempDir(), "\n", 0o600) },
		"with a space":          func() string { return writeToken(t, t.TempDir(), "two words", 0o600) },
		"two lines":             func() string { return writeToken(t, t.TempDir(), "one\ntwo\n", 0o600) },
		"over its bound":        func() string { return writeToken(t, t.TempDir(), strings.Repeat("a", maxGatewayTokenBytes+1), 0o600) },
		"a link": func() string {
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(writeToken(t, t.TempDir(), "token", 0o600), link); err != nil {
				t.Fatal(err)
			}
			return link
		},
		"missing": func() string { return filepath.Join(t.TempDir(), "none") },
	} {
		_, err := readGatewayToken(file())
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "token\"") || strings.Contains(err.Error(), t.TempDir()) {
			t.Errorf("%s: the error names the token or its path: %v", name, err)
		}
	}
}

// fakeDiscovery records the bearer token of every call.
type fakeDiscovery struct {
	tosservicev1connect.UnimplementedCapabilityDiscoveryServiceHandler
	mu     sync.Mutex
	tokens []string
}

func (f *fakeDiscovery) RequestQuoteProposal(_ context.Context,
	request *connect.Request[nativev1.RequestQuoteProposalRequest]) (*connect.Response[nativev1.RequestQuoteProposalResponse], error) {
	f.mu.Lock()
	f.tokens = append(f.tokens, request.Header().Get("Authorization"))
	f.mu.Unlock()
	return connect.NewResponse(&nativev1.RequestQuoteProposalResponse{ProviderKeyCardPacketJson: []byte("{}")}), nil
}

func (f *fakeDiscovery) ListCapabilities(_ context.Context,
	request *connect.Request[nativev1.ListCapabilitiesRequest]) (*connect.Response[nativev1.ListCapabilitiesResponse], error) {
	f.mu.Lock()
	f.tokens = append(f.tokens, request.Header().Get("Authorization"))
	f.mu.Unlock()
	return connect.NewResponse(&nativev1.ListCapabilitiesResponse{}), nil
}

// The gateway client trusts only the pinned CA and reads the token for
// every call, so a rotated token is sent at once.
func TestTheGatewayClientPinsItsCAAndReadsTheTokenPerCall(t *testing.T) {
	handler := &fakeDiscovery{}
	path, service := tosservicev1connect.NewCapabilityDiscoveryServiceHandler(handler)
	mux := http.NewServeMux()
	mux.Handle(path, service)
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	dir := t.TempDir()
	pinned := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(pinned, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tokenFile := writeToken(t, dir, "first", 0o600)
	client, err := newGatewayClient(server.URL, pinned, tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.RequestQuoteProposal(context.Background(), &nativev1.RequestQuoteProposalRequest{}); err != nil {
		t.Fatal(err)
	}
	writeToken(t, dir, "second", 0o600)
	if _, err := client.ListCapabilities(context.Background(), &nativev1.ListCapabilitiesRequest{}); err != nil {
		t.Fatal(err)
	}
	if len(handler.tokens) != 2 || handler.tokens[0] != "Bearer first" || handler.tokens[1] != "Bearer second" {
		t.Fatalf("tokens sent: %v", handler.tokens)
	}
	// A token made readable by others is no longer sent.
	if err := os.Chmod(tokenFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListCapabilities(context.Background(), &nativev1.ListCapabilitiesRequest{}); err == nil || len(handler.tokens) != 2 {
		t.Fatal("a token readable by others was sent")
	}
	if err := os.Chmod(tokenFile, 0o600); err != nil {
		t.Fatal(err)
	}
	// Without the pinned CA the gateway's certificate is not trusted.
	other, err := newGatewayClient(server.URL, "", tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.ListCapabilities(context.Background(), &nativev1.ListCapabilitiesRequest{}); err == nil {
		t.Fatal("a gateway certificate outside the pinned CAs was trusted")
	}
	transport, err := gatewayTransport(pinned)
	if err != nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("transport: %v", err)
	}
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := gatewayTransport(junk); err == nil {
		t.Fatal("a CA file without a certificate was accepted")
	}
	if _, err := newGatewayClient(server.URL, pinned, filepath.Join(dir, "none")); err == nil {
		t.Fatal("a gateway without a readable token was opened")
	}
}
