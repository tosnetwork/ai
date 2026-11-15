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
	"sync"
	"syscall"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
)

type options struct {
	listen         string
	tlsCert        string
	tlsKey         string
	stateDir       string
	basePath       string
	ttl            time.Duration
	recipientCount int
	recipientBytes int64
	clientCount    int
	globalEntries  int
	globalBytes    int64
	depositRate    int
	depositBurst   int
	readRate       int
	readBurst      int
	maxRateClients int
	maxConnections int
	sweepInterval  time.Duration
	trustedProxies []netip.Prefix
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
	flags.IntVar(&opts.maxConnections, "max-connections", 1024, "concurrent connections")
	flags.DurationVar(&opts.sweepInterval, "sweep-interval", time.Minute, "expiry sweep interval")
	flags.Var(prefixList{&opts.trustedProxies}, "trusted-proxy", "address or CIDR of a TLS-terminating proxy whose X-Forwarded-For is believed (repeatable; default none)")
	if err := flags.Parse(args); err != nil {
		return options{}, err
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
	if opts.maxConnections <= 0 || opts.sweepInterval < time.Second || opts.maxRateClients <= 0 {
		return options{}, errors.New("-max-connections, -max-rate-clients must be positive and -sweep-interval at least 1s")
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

// limitListener bounds concurrent connections; an accept past the bound
// waits for a connection to close.
type limitListener struct {
	net.Listener
	slots chan struct{}
}

func (l *limitListener) Accept() (net.Conn, error) {
	l.slots <- struct{}{}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitConn{Conn: conn, release: func() { <-l.slots }}, nil
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
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
		MaxRateClients: opts.maxRateClients, TrustedProxies: opts.trustedProxies, Logger: logger})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", opts.listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	listener = &limitListener{Listener: listener, slots: make(chan struct{}, opts.maxConnections)}
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 16 << 10,
		// Connection-level errors name client addresses; they are dropped
		// rather than logged.
		ErrorLog: log.New(io.Discard, "", 0)}
	sweepCtx, stopSweep := context.WithCancel(ctx)
	defer stopSweep()
	go store.RunSweeper(sweepCtx, opts.sweepInterval, time.Now, func(err error) {
		logger.Error("expiry sweep", "error", err)
	})
	errCh := make(chan error, 1)
	go func() { errCh <- server.Serve(listener) }()
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
