// Command tos-service-packet-relay runs an Agent Packet Relay V1 mailbox: a
// bounded store of end-to-end-encrypted envelopes. It holds no key, never
// decrypts and has no chain access.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
)

type options struct {
	listen            string
	tlsCert           string
	tlsKey            string
	stateDir          string
	basePath          string
	ttl               time.Duration
	recipientCount    int
	recipientBytes    int64
	clientCount       int
	globalEntries     int
	globalBytes       int64
	depositRate       int
	depositBurst      int
	readRate          int
	readBurst         int
	maxRateClients    int
	maxConnections    int
	maxPerClientConns int
	maxSiteConns      int
	maxDeposits       int
	maxClientDeposits int
	maxSiteDeposits   int
	sweepInterval     time.Duration
	trustedProxies    []netip.Prefix
}

type prefixList struct{ values *[]netip.Prefix }

func (p prefixList) String() string {
	if p.values == nil {
		return ""
	}
	parts := make([]string, 0, len(*p.values))
	for _, prefix := range *p.values {
		parts = append(parts, prefix.String())
	}
	return strings.Join(parts, ",")
}

func (p prefixList) Set(value string) error {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		addr, addrErr := netip.ParseAddr(strings.TrimSpace(value))
		if addrErr != nil {
			return fmt.Errorf("trusted proxy %q is neither an address nor a CIDR prefix", value)
		}
		prefix = netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen())
	}
	if prefix.Addr().Is4In6() {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	*p.values = append(*p.values, prefix.Masked())
	return nil
}

func parseOptions(args []string, output io.Writer) (options, error) {
	var opts options
	flags := flag.NewFlagSet("tos-service-packet-relay", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.StringVar(&opts.listen, "listen", "127.0.0.1:8095", "listen address; plain HTTP only on a loopback address")
	flags.StringVar(&opts.tlsCert, "tls-cert", "", "server TLS certificate (PEM); with -tls-key serves HTTPS")
	flags.StringVar(&opts.tlsKey, "tls-key", "", "server TLS private key (PEM)")
	flags.StringVar(&opts.stateDir, "state-dir", "", "absolute durable state directory (required)")
	flags.StringVar(&opts.basePath, "base-path", "", "path of the relay base URL, e.g. /relay (default: none)")
	flags.DurationVar(&opts.ttl, "ttl", agentpacketrelay.MaxTTL, "retention after receipt, at most 24h")
	flags.IntVar(&opts.recipientCount, "per-recipient-max-envelopes", agentpacketrelay.MaxPerRecipientEnvelopes, "envelopes per recipient (at most 256)")
	flags.Int64Var(&opts.recipientBytes, "per-recipient-max-bytes", agentpacketrelay.MaxPerRecipientBytes, "envelope bytes per recipient (at most 16 MiB)")
	flags.IntVar(&opts.clientCount, "per-client-recipient-max-envelopes", agentpacketrelay.MaxPerClientRecipientEnvelopes, "envelopes per (client address, recipient) (at most 64)")
	flags.IntVar(&opts.globalEntries, "global-max-entries", 0, "stored envelopes plus tombstones (required)")
	flags.Int64Var(&opts.globalBytes, "global-max-bytes", 0, "stored envelope bytes (required)")
	flags.IntVar(&opts.depositRate, "deposit-rate-per-minute", agentpacketrelay.DefaultDepositRate.PerMinute, "deposits per client address per minute")
	flags.IntVar(&opts.depositBurst, "deposit-burst", agentpacketrelay.DefaultDepositRate.Burst, "deposit burst per client address")
	flags.IntVar(&opts.readRate, "read-rate-per-minute", agentpacketrelay.DefaultReadRate.PerMinute, "list, download and acknowledge requests per client address per minute")
	flags.IntVar(&opts.readBurst, "read-burst", agentpacketrelay.DefaultReadRate.Burst, "list, download and acknowledge burst per client address")
	flags.IntVar(&opts.maxRateClients, "max-rate-clients", agentpacketrelay.DefaultMaxRateClients, "client addresses tracked per rate-limiter table")
	flags.IntVar(&opts.maxConnections, "max-connections", agentpacketrelay.DefaultMaxConnections, "concurrent connections; more are closed at accept")
	flags.IntVar(&opts.maxPerClientConns, "max-connections-per-client", agentpacketrelay.DefaultMaxConnectionsPerClient,
		"concurrent connections per TCP peer address (IPv6 per /64); trusted proxies are exempt")
	flags.IntVar(&opts.maxClientDeposits, "max-concurrent-deposits-per-client", agentpacketrelay.DefaultMaxConcurrentDepositsPerClient,
		"deposit bodies one client address holds at once; past it 429")
	flags.IntVar(&opts.maxSiteConns, "max-connections-per-48", agentpacketrelay.DefaultMaxConnectionsPer48,
		"concurrent connections of all peers in one IPv6 /48; trusted proxies are exempt")
	flags.IntVar(&opts.maxDeposits, "max-concurrent-deposits", agentpacketrelay.DefaultMaxConcurrentDeposits, "deposit bodies held in memory at once (256 KiB each)")
	flags.IntVar(&opts.maxSiteDeposits, "max-concurrent-deposits-per-48", agentpacketrelay.DefaultMaxConcurrentDepositsPer48,
		"deposit bodies all clients in one IPv6 /48 hold at once; past it 429")
	flags.DurationVar(&opts.sweepInterval, "sweep-interval", time.Minute, "expiry sweep interval")
	flags.Var(prefixList{&opts.trustedProxies}, "trusted-proxy", "address or CIDR of a TLS-terminating proxy whose X-Forwarded-For is believed (repeatable; default none)")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	// A share flag left unset is passed as zero, so the relay takes its
	// default clamped to the totals; one that is set must be positive, and
	// the relay checks per client <= per /48 <= total.
	set := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { set[f.Name] = true })
	for name, value := range map[string]*int{
		"max-connections-per-client": &opts.maxPerClientConns, "max-connections-per-48": &opts.maxSiteConns,
		"max-concurrent-deposits-per-client": &opts.maxClientDeposits, "max-concurrent-deposits-per-48": &opts.maxSiteDeposits,
	} {
		if !set[name] {
			*value = 0
		} else if *value <= 0 {
			return options{}, fmt.Errorf("-%s must be positive", name)
		}
	}
	if flags.NArg() != 0 {
		return options{}, errors.New("unexpected positional arguments")
	}
	if opts.stateDir == "" {
		return options{}, errors.New("-state-dir is required")
	}
	if opts.globalEntries <= 0 || opts.globalBytes <= 0 {
		return options{}, errors.New("-global-max-entries and -global-max-bytes are required")
	}
	if opts.maxConnections <= 0 || opts.maxDeposits <= 0 || opts.sweepInterval < time.Second || opts.maxRateClients <= 0 {
		return options{}, errors.New("-max-connections, -max-concurrent-deposits and -max-rate-clients must be positive " +
			"and -sweep-interval at least 1s")
	}
	return opts, nil
}

func (o options) limits() agentpacketrelay.Limits {
	return agentpacketrelay.Limits{PerRecipientMaxEnvelopes: o.recipientCount, PerRecipientMaxBytes: o.recipientBytes,
		PerClientRecipientMaxEnvelopes: o.clientCount, GlobalMaxEntries: o.globalEntries, GlobalMaxBytes: o.globalBytes,
		TTL: o.ttl}
}

// buildServerTLS serves HTTPS with a certificate, or plain HTTP only on a
// loopback listen address (behind a local TLS-terminating proxy).
func buildServerTLS(listen, certFile, keyFile string) (*tls.Config, error) {
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("-tls-cert and -tls-key must be set together")
	}
	if certFile == "" {
		host, _, err := net.SplitHostPort(listen)
		if err != nil {
			return nil, fmt.Errorf("invalid listen address: %w", err)
		}
		addr, err := netip.ParseAddr(host)
		if host != "localhost" && (err != nil || !addr.IsLoopback()) {
			return nil, errors.New("plain HTTP is restricted to a loopback listen address; set -tls-cert and -tls-key")
		}
		return nil, nil
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}, nil
}

func run(ctx context.Context, args []string, output io.Writer, ready func(net.Addr)) error {
	opts, err := parseOptions(args, output)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(output, nil))
	tlsConfig, err := buildServerTLS(opts.listen, opts.tlsCert, opts.tlsKey)
	if err != nil {
		return err
	}
	store, err := agentpacketrelay.OpenDiskStore(opts.stateDir, opts.limits(), time.Now())
	if err != nil {
		return fmt.Errorf("open relay store: %w", err)
	}
	defer store.Close()
	handler, err := agentpacketrelay.NewServer(agentpacketrelay.ServerConfig{Store: store, BasePath: opts.basePath,
		DepositRate:    agentpacketrelay.RateLimit{PerMinute: opts.depositRate, Burst: opts.depositBurst},
		ReadRate:       agentpacketrelay.RateLimit{PerMinute: opts.readRate, Burst: opts.readBurst},
		MaxRateClients: opts.maxRateClients, MaxConcurrentDeposits: opts.maxDeposits,
		MaxConcurrentDepositsPerClient: opts.maxClientDeposits, MaxConcurrentDepositsPer48: opts.maxSiteDeposits,
		TrustedProxies: opts.trustedProxies, Logger: logger})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", opts.listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	// The TCP peer is the only address known at accept time. A connection
	// past either bound is closed at once instead of waiting for a slot, so
	// shutdown and other clients are never blocked behind a full table.
	listener, err = agentpacketrelay.NewLimitListener(listener, agentpacketrelay.ListenerLimits{
		MaxConnections: opts.maxConnections, MaxConnectionsPerClient: opts.maxPerClientConns,
		MaxConnectionsPer48: opts.maxSiteConns, TrustedProxies: opts.trustedProxies})
	if err != nil {
		return err
	}
	// IdleTimeout lets a poller keep its connection between 15-second polls
	// (plus jitter) and frees an idle one soon after.
	server := &http.Server{Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		// Connection-level errors name client addresses; they are dropped
		// rather than logged.
		ErrorLog: log.New(io.Discard, "", 0)}
	sweepCtx, stopSweep := context.WithCancel(ctx)
	defer stopSweep()
	go store.RunSweeper(sweepCtx, opts.sweepInterval, time.Now, func(err error) {
		logger.Error("expiry sweep", "error", err)
	})
	errCh := make(chan error, 1)
	go func() {
		if tlsConfig != nil {
			// ServeTLS negotiates HTTP/2 as well as HTTP/1.1.
			errCh <- server.ServeTLS(listener, "", "")
			return
		}
		errCh <- server.Serve(listener)
	}()
	logger.Info("agent packet relay listening", "address", listener.Addr().String(), "tls", tlsConfig != nil,
		"usage", store.Usage())
	if ready != nil {
		ready(listener.Addr())
	}
	select {
	case <-ctx.Done():
	case serveErr := <-errCh:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("serve: %w", serveErr)
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, nil); err != nil {
		fmt.Fprintln(os.Stderr, "tos-service-packet-relay:", err)
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}
}
