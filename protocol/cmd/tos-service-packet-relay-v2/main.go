// Command tos-service-packet-relay-v2 serves V2 only. It holds no signing key
// and reads finalized registry state through the existing majority reader.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

type config struct {
	Directory         bool                       `json:"directory"`
	DirectoryAgents   int                        `json:"directory_agents,omitempty"`
	RevocationEntries int                        `json:"revocation_entries,omitempty"`
	MaxWaiters        int                        `json:"max_waiters,omitempty"`
	TTLSeconds        *uint64                    `json:"ttl_seconds,omitempty"`
	TrustedProxies    []string                   `json:"trusted_proxies,omitempty"`
	StrangerCount     *int                       `json:"stranger_max_envelopes,omitempty"`
	StrangerBytes     *int64                     `json:"stranger_max_bytes,omitempty"`
	StrangerShare     *int                       `json:"stranger_global_share,omitempty"`
	Listen            string                     `json:"listen"`
	URL               string                     `json:"url"`
	TLSCert           string                     `json:"tls_cert"`
	TLSKey            string                     `json:"tls_key"`
	StateDir          string                     `json:"state_dir"`
	Checkpoint        string                     `json:"checkpoint"`
	GlobalEntries     int                        `json:"global_entries"`
	GlobalBytes       int64                      `json:"global_bytes"`
	Endpoints         []string                   `json:"endpoints"`
	Mode              agenttransport.NetworkMode `json:"mode"`
	Network           *nativev1.NetworkDomain    `json:"network"`
	CodeBase64        string                     `json:"code_base64"`
	CodeHash          string                     `json:"code_hash"`
}

func readConfig(path string) (config, error) {
	var c config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return c, err
	}
	if len(raw) > 65536 {
		return c, errors.New("configuration too large")
	}
	if err = jsonstrict.Decode(raw, &c); err != nil {
		return c, errors.New("invalid V2 configuration")
	}
	if c.Listen == "" || c.Network == nil || !filepath.IsAbs(c.StateDir) || !filepath.IsAbs(c.Checkpoint) || c.StateDir == c.Checkpoint {
		return c, errors.New("explicit listen, network, state directory and checkpoint required")
	}
	relative, err := filepath.Rel(c.StateDir, c.Checkpoint)
	if err != nil || filepath.Clean(c.StateDir) != c.StateDir || filepath.Clean(c.Checkpoint) != c.Checkpoint || relative == "." || (!strings.HasPrefix(relative, ".."+string(os.PathSeparator)) && relative != "..") {
		return c, errors.New("checkpoint must be outside the V2 store")
	}
	return c, nil
}
func verifier(c config) (*agenttransport.Verifier, error) {
	// Native registry serialization uses prefixed genesis hashes. Normalize only
	// the configured copy; both constructors enforce the exact approved genesis.
	nativeNetwork := &nativev1.NetworkDomain{NetworkId: c.Network.NetworkId, GenesisRootHash: c.Network.GenesisRootHash, GenesisFileHash: c.Network.GenesisFileHash}
	nativeNetwork.GenesisRootHash = "sha256:" + c.Network.GenesisRootHash
	nativeNetwork.GenesisFileHash = "sha256:" + c.Network.GenesisFileHash
	locator, err := nativecore.NewLocator(nativeNetwork, 0, c.CodeBase64, c.CodeHash)
	if err != nil {
		return nil, err
	}
	adapter, err := toschain.New(toschain.Config{Network: c.Network.NetworkId, Endpoints: c.Endpoints, Quorum: len(c.Endpoints)/2 + 1})
	if err != nil {
		return nil, err
	}
	source, err := toschain.NewSimplifiedNativeResolver(adapter, locator, c.Checkpoint)
	if err != nil {
		return nil, err
	}
	return agentpacketrelay.NewV2FinalizedVerifier(agenttransport.Config{Mode: c.Mode, Network: c.Network, ChainPolicy: agenttransport.ChainPolicy{RegistryCodeHashes: []string{c.CodeHash}, Locator: registryLocator{locator}}}, pinnedReader{source, adapter, nativeNetwork})
}

type registryLocator struct{ l *nativecore.Locator }

func (l registryLocator) Locate(code, id string) (string, error) {
	if code != l.l.CodeHash {
		return "", errors.New("unknown registry code")
	}
	identity, err := l.l.Locate(id)
	return identity.Address, err
}
func serve(ctx context.Context, c config, ready func(net.Addr)) error {
	if len(c.TrustedProxies) > 16 {
		return errors.New("too many trusted proxy prefixes")
	}
	var proxies []netip.Prefix
	for _, text := range c.TrustedProxies {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || prefix != prefix.Masked() {
			return errors.New("invalid trusted proxy prefix")
		}
		proxies = append(proxies, prefix)
	}
	limits, err := c.limits()
	if err != nil {
		return err
	}
	v, err := verifier(c)
	if err != nil {
		return err
	}
	var tlsConfig *tls.Config
	if c.TLSCert != "" || c.TLSKey != "" {
		pair, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
		if err != nil {
			return errors.New("invalid TLS key pair")
		}
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	} else {
		host, _, err := net.SplitHostPort(c.Listen)
		if err != nil {
			return err
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.IsLoopback() {
			return errors.New("plaintext listener must be numeric loopback behind a TLS proxy")
		}
	}
	store, err := agentpacketrelay.OpenV2Store(c.StateDir, limits, time.Now(), agentpacketrelay.V2OpenOptions{DirectoryAgents: c.DirectoryAgents, RevocationEntries: c.RevocationEntries, MaxWaiters: c.MaxWaiters})
	if err != nil {
		return err
	}
	defer store.Close()
	handler, err := agentpacketrelay.NewV2Server(agentpacketrelay.V2ServerConfig{Store: store, URL: c.URL, Verifier: v, TrustedProxies: proxies, Directory: c.Directory})
	if err != nil {
		return err
	}
	inner, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	defer inner.Close()
	listener, err := agentpacketrelay.NewLimitListener(inner, agentpacketrelay.ListenerLimits{TrustedProxies: proxies})
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	maintenance, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	defer func() { stop(); <-done }()
	go func() {
		defer close(done)
		agentpacketrelay.RunV2Maintenance(maintenance, store, time.Now, func() {
			fmt.Fprintln(os.Stderr, "V2 maintenance refused; admission remains bounded by its durable mark")
		})
	}()
	errorsCh := make(chan error, 1)
	go func() {
		if tlsConfig != nil {
			errorsCh <- server.ServeTLS(listener, "", "")
		} else {
			errorsCh <- server.Serve(listener)
		}
	}()
	if ready != nil {
		ready(listener.Addr())
	}
	var result error
	select {
	case <-ctx.Done():
	case result = <-errorsCh:
		if errors.Is(result, http.ErrServerClosed) {
			result = nil
		}
	}
	drain, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(drain); err != nil {
		result = errors.Join(result, err)
		result = errors.Join(result, server.Close())
	}
	return result
}
func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("tos-service-packet-relay-v2", flag.ContinueOnError)
	var path string
	flags.StringVar(&path, "config", "", "V2-only JSON configuration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || path == "" {
		return errors.New("config required")
	}
	c, err := readConfig(path)
	if err != nil {
		return err
	}
	return serve(ctx, c, nil)
}
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "V2 relay refused to run")
		os.Exit(2)
	}
}

type pinnedReader struct {
	source  *toschain.SimplifiedNativeResolver
	chain   *toschain.Adapter
	network *nativev1.NetworkDomain
}

func (r pinnedReader) ResolveState(ctx context.Context, id, hash string) (*nativev1.NativeStateV1, bool, error) {
	if err := r.chain.CheckNetworkGenesis(ctx, r.network.GenesisRootHash, r.network.GenesisFileHash); err != nil {
		return nil, false, err
	}
	return r.source.ResolveState(ctx, id, hash)
}

func (c config) limits() (agentpacketrelay.V2Limits, error) {
	limits := agentpacketrelay.DefaultV2Limits(c.GlobalEntries, c.GlobalBytes)
	if c.StrangerCount != nil {
		limits.StrangerMaxEnvelopes = *c.StrangerCount
	}
	if c.StrangerBytes != nil {
		limits.StrangerMaxBytes = *c.StrangerBytes
	}
	if c.StrangerShare != nil {
		limits.StrangerGlobalPercent = *c.StrangerShare
	}

	if c.TTLSeconds != nil {
		if *c.TTLSeconds == 0 || *c.TTLSeconds > uint64(agentpacketrelay.MaxTTL/time.Second) {
			return limits, errors.New("invalid retention seconds")
		}
		limits.Base.TTL = time.Duration(*c.TTLSeconds) * time.Second
	}
	return limits, limits.Validate()
}
