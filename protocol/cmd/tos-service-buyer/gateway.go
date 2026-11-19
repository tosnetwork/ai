package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/gen/tos/service/v1/tosservicev1connect"
	"github.com/tosnetwork/ai/protocol/internal/osguard"
	"github.com/tosnetwork/ai/protocol/pkg/serviceactorindex"
)

// Gateway bounds. A gateway is a hint source and a Quote source only: the
// agent re-verifies everything it serves against finalized state.
const (
	gatewayCallTimeout   = 30 * time.Second
	gatewayMessageBytes  = 4 << 20
	maxGatewayTokenBytes = 4096
)

// checkGatewayURL accepts an https base URL, or an http one whose host is a
// loopback address, with no user, path, query or fragment.
func checkGatewayURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.String() != raw {
		return nil, errors.New("gateway_url must be a bare http(s) base URL")
	}
	switch parsed.Scheme {
	case "https":
		return parsed, nil
	case "http":
		host := parsed.Hostname()
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return parsed, nil
		}
		return nil, errors.New("gateway_url may use http only on a loopback address")
	}
	return nil, errors.New("gateway_url must be https, or http on a loopback address")
}

// checkGatewayConfig validates the optional gateway and catalog fields.
func checkGatewayConfig(config agentConfig) error {
	if config.GatewayURL == "" {
		if config.GatewayCAFile != "" || config.GatewayTokenFile != "" {
			return errors.New("gateway_ca_file and gateway_token_file need a gateway_url")
		}
	} else {
		parsed, err := checkGatewayURL(config.GatewayURL)
		if err != nil {
			return err
		}
		if parsed.Scheme == "https" && config.GatewayCAFile == "" {
			return errors.New("an https gateway is configured but gateway_ca_file pins no CA")
		}
		if parsed.Scheme == "http" && config.GatewayCAFile != "" {
			return errors.New("gateway_ca_file pins a CA for a plaintext gateway")
		}
		if !cleanAbsolute(config.GatewayTokenFile) {
			return errors.New("a gateway needs gateway_token_file, an absolute clean path")
		}
		if config.GatewayCAFile != "" && !cleanAbsolute(config.GatewayCAFile) {
			return errors.New("gateway_ca_file must be an absolute clean path")
		}
	}
	if config.CatalogDir != "" && !cleanAbsolute(config.CatalogDir) {
		return errors.New("catalog_dir must be an absolute clean path")
	}
	return nil
}

func cleanAbsolute(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }

// gatewayTransport verifies the gateway against the pinned CA certificates
// only, never the system pool, with TLS 1.2 at least.
func gatewayTransport(caFile string) (*http.Transport, error) {
	pool := x509.NewCertPool()
	if caFile != "" {
		raw, err := readBounded(caFile, 1<<20)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(raw) {
			return nil, errors.New("the gateway CA file holds no PEM certificate")
		}
	}
	return &http.Transport{
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  gatewayCallTimeout,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        90 * time.Second,
		MaxResponseHeaderBytes: 16 << 10,
		ForceAttemptHTTP2:      true,
	}, nil
}

// errGatewayToken is every failure to read the token; it never carries the
// token or its path.
var errGatewayToken = errors.New("the gateway token file is not an owner-private regular file holding one token")

// readGatewayToken reads the bearer token anew for each call, so a rotated
// token takes effect at once and the agent holds it no longer than a call.
// The file must be owner-private and hold one token of visible ASCII.
func readGatewayToken(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !osguard.CurrentUserOwns(info) ||
		info.Size() > maxGatewayTokenBytes+1 {
		return "", errGatewayToken
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errGatewayToken
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxGatewayTokenBytes+2))
	if err != nil {
		return "", errGatewayToken
	}
	token := strings.TrimSuffix(string(raw), "\n")
	if token == "" || len(token) > maxGatewayTokenBytes {
		return "", errGatewayToken
	}
	for index := 0; index < len(token); index++ {
		if token[index] < 0x21 || token[index] > 0x7e {
			return "", errGatewayToken
		}
	}
	return token, nil
}

// gatewayClient calls a gateway's CapabilityDiscoveryService with the
// bearer token read per call. buyeragent uses it as a hint source and a
// Quote source; it holds no authority.
type gatewayClient struct {
	tokenFile string
	discovery tosservicev1connect.CapabilityDiscoveryServiceClient
}

func newGatewayClient(baseURL, caFile, tokenFile string) (*gatewayClient, error) {
	parsed, err := checkGatewayURL(baseURL)
	if err != nil {
		return nil, err
	}
	transport, err := gatewayTransport(caFile)
	if err != nil {
		return nil, err
	}
	if _, err := readGatewayToken(tokenFile); err != nil {
		return nil, err
	}
	base := strings.TrimSuffix(parsed.String(), "/")
	httpClient := &http.Client{Transport: transport, Timeout: gatewayCallTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &gatewayClient{tokenFile: tokenFile, discovery: tosservicev1connect.NewCapabilityDiscoveryServiceClient(httpClient,
		base, connect.WithReadMaxBytes(gatewayMessageBytes), connect.WithSendMaxBytes(gatewayMessageBytes))}, nil
}

func gatewayCall[Req, Res any](g *gatewayClient, ctx context.Context, message *Req,
	call func(context.Context, *connect.Request[Req]) (*connect.Response[Res], error)) (*Res, error) {
	token, err := readGatewayToken(g.tokenFile)
	if err != nil {
		return nil, err
	}
	request := connect.NewRequest(message)
	request.Header().Set("Authorization", "Bearer "+token)
	callCtx, cancel := context.WithTimeout(ctx, gatewayCallTimeout)
	defer cancel()
	response, err := call(callCtx, request)
	if err != nil {
		return nil, err
	}
	return response.Msg, nil
}

func (g *gatewayClient) ListCapabilities(ctx context.Context, request *nativev1.ListCapabilitiesRequest) (*nativev1.ListCapabilitiesResponse, error) {
	return gatewayCall(g, ctx, request, g.discovery.ListCapabilities)
}

func (g *gatewayClient) SearchCapabilities(ctx context.Context, request *nativev1.SearchCapabilitiesRequest) (*nativev1.SearchCapabilitiesResponse, error) {
	return gatewayCall(g, ctx, request, g.discovery.SearchCapabilities)
}

func (g *gatewayClient) GetSoftwareWorkManifest(ctx context.Context,
	request *nativev1.GetSoftwareWorkManifestRequest) (*nativev1.GetSoftwareWorkManifestResponse, error) {
	return gatewayCall(g, ctx, request, g.discovery.GetSoftwareWorkManifest)
}

func (g *gatewayClient) RequestQuoteProposal(ctx context.Context,
	request *nativev1.RequestQuoteProposalRequest) (*nativev1.RequestQuoteProposalResponse, error) {
	return gatewayCall(g, ctx, request, g.discovery.RequestQuoteProposal)
}

// finalizedResolver answers a local capability catalog's Capability reads
// from finalized state, one checkpoint per read.
type finalizedResolver struct{ reader serviceactorindex.Reader }

func (f finalizedResolver) ResolveNativeState(ctx context.Context,
	request *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error) {
	session, err := f.reader.BeginSession(ctx)
	if err != nil {
		return nil, err
	}
	state, found, err := session.ResolveRegistry(ctx, request.GetObjectId())
	if err != nil {
		return nil, err
	}
	return &nativev1.ResolveNativeStateResponse{Found: found, State: state}, nil
}
