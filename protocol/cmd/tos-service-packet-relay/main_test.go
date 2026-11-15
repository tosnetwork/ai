package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

func TestPlainHTTPRestrictedToLoopback(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:8095", "[::1]:8095", "localhost:8095"} {
		if config, err := buildServerTLS(listen, "", ""); err != nil || config != nil {
			t.Fatalf("%s: %v", listen, err)
		}
	}
	for _, listen := range []string{"0.0.0.0:8095", ":8095", "192.0.2.1:8095", "[::]:8095"} {
		if _, err := buildServerTLS(listen, "", ""); err == nil {
			t.Fatalf("plain HTTP on %s accepted", listen)
		}
	}
	if _, err := buildServerTLS("127.0.0.1:8095", "/tmp/cert", ""); err == nil {
		t.Fatal("unpaired TLS certificate accepted")
	}
}

func TestOptions(t *testing.T) {
	base := []string{"-state-dir", "/var/lib/relay", "-global-max-entries", "1000", "-global-max-bytes", "1073741824"}
	opts, err := parseOptions(base, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if err := opts.limits().Validate(); err != nil {
		t.Fatalf("default limits: %v", err)
	}
	if len(opts.trustedProxies) != 0 {
		t.Fatal("a trusted proxy is configured by default")
	}
	for name, args := range map[string][]string{
		"no state dir":     {"-global-max-entries", "1", "-global-max-bytes", "1"},
		"no global count":  {"-state-dir", "/x", "-global-max-bytes", "1"},
		"no global bytes":  {"-state-dir", "/x", "-global-max-entries", "1"},
		"positional":       append(append([]string(nil), base...), "extra"),
		"bad proxy":        append(append([]string(nil), base...), "-trusted-proxy", "example.com"),
		"zero connections": append(append([]string(nil), base...), "-max-connections", "0"),
	} {
		if _, err := parseOptions(args, io.Discard); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	opts, err = parseOptions(append(append([]string(nil), base...), "-trusted-proxy", "127.0.0.1", "-trusted-proxy", "10.0.0.0/8",
		"-trusted-proxy", "::ffff:192.0.2.0/120"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := (prefixList{&opts.trustedProxies}).String(); got !="127.0.0.1/32,10.0.0.0/8,192.0.2.0/24" {
		t.Fatalf("trusted proxies = %s", got)
	}
	opts, err = parseOptions(append(append([]string(nil), base...), "-ttl", "25h"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if opts.limits().Validate() == nil {
		t.Fatal("a TTL over 24 h validated")
	}
}

type daemon struct {
	addr   net.Addr
	cancel context.CancelFunc
	done   chan error
	output *bytes.Buffer
}

func startDaemon(t *testing.T, args ...string) *daemon {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan net.Addr, 1)
	d := &daemon{cancel: cancel, done: make(chan error, 1), output: &bytes.Buffer{}}
	// The JSON log handler serializes its writes; the buffer is read only
	// after run returns.
	go func() { d.done <- run(ctx, args, d.output, func(addr net.Addr) { ready <- addr }) }()
	select {
	case d.addr = <-ready:
	case err := <-d.done:
		t.Fatalf("daemon exited: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("daemon did not start")
	}
	return d
}

func (d *daemon) stop(t *testing.T) {
	t.Helper()
	d.cancel()
	if err := <-d.done; err != nil {
		t.Fatalf("daemon stop: %v", err)
	}
}

func sealFor(t *testing.T) (string, []byte) {
	t.Helper()
	var digest [32]byte
	if _, err := rand.Read(digest[:]); err != nil {
		t.Fatal(err)
	}
	agentID := agentpacketseal.AgentID(digest)
	seed, err := agentpacketseal.GenerateSeed()
	if err != nil {
		t.Fatal(err)
	}
	key, err := agentpacketseal.NewPrivateKey(agentID, seed)
	if err != nil {
		t.Fatal(err)
	}
	public, err := key.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	envelope, err := agentpacketseal.Seal(agentpacketseal.RecipientKey{AgentID: agentID, KeyID: key.KeyID, PublicKey: public},
		secret, []byte(`{"daemon":"test"}`), uint64(time.Now().Unix())+600)
	if err != nil {
		t.Fatal(err)
	}
	return agentID, envelope
}

// TestDaemonServesAndSurvivesRestart runs the daemon over loopback HTTP,
// deposits, restarts it on the same state directory and lists again.
func TestDaemonServesAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	args := []string{"-listen", "127.0.0.1:0", "-state-dir", dir, "-global-max-entries", "100",
		"-global-max-bytes", "67108864", "-base-path", "/relay"}
	d := startDaemon(t, args...)
	client, err := agentpacketrelay.NewClient(agentpacketrelay.ClientConfig{BaseURL: "http://" + d.addr.String() + "/relay"})
	if err != nil {
		t.Fatal(err)
	}
	agentID, envelope := sealFor(t)
	if outcome, err := client.Deposit(context.Background(), envelope); err != nil || outcome.Result != agentpacketrelay.DepositStored {
		t.Fatalf("deposit = %+v, %v", outcome, err)
	}
	d.stop(t)
	if strings.Contains(d.output.String(), agentID[len("agent_"):]) {
		t.Fatal("the daemon logged an Agent ID")
	}

	d = startDaemon(t, args...)
	defer d.stop(t)
	client, err = agentpacketrelay.NewClient(agentpacketrelay.ClientConfig{BaseURL: "http://" + d.addr.String() + "/relay"})
	if err != nil {
		t.Fatal(err)
	}
	mailbox, err := client.List(context.Background(), agentID)
	if err != nil || len(mailbox.Envelopes) != 1 {
		t.Fatalf("list after restart = %+v, %v", mailbox, err)
	}
	if outcome, err := client.Deposit(context.Background(), envelope); err != nil || outcome.Result != agentpacketrelay.DepositDuplicate {
		t.Fatalf("re-deposit after restart = %+v, %v", outcome, err)
	}
	// A second daemon on the same state directory is refused.
	if err := run(context.Background(), append([]string(nil), args...), io.Discard, nil); err == nil {
		t.Fatal("a second daemon opened a held state directory")
	}
}

// TestDaemonTLS serves HTTPS with a certificate and reaches it through a
// client pinned to that certificate.
func TestDaemonTLS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, pool := selfSigned(t, dir)
	d := startDaemon(t, "-listen", "127.0.0.1:0", "-tls-cert", certFile, "-tls-key", keyFile,
		"-state-dir", filepath.Join(dir, "state"), "-global-max-entries", "100", "-global-max-bytes", "67108864")
	defer d.stop(t)
	_, port, err := net.SplitHostPort(d.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}
	client, err := agentpacketrelay.NewClient(agentpacketrelay.ClientConfig{BaseURL: "https://localhost:" + port, Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	_, envelope := sealFor(t)
	if outcome, err := client.Deposit(context.Background(), envelope); err != nil || outcome.Result != agentpacketrelay.DepositStored {
		t.Fatalf("TLS deposit = %+v, %v", outcome, err)
	}
	// Plain HTTP to the TLS port gets no relay answer.
	plain, err := agentpacketrelay.NewClient(agentpacketrelay.ClientConfig{BaseURL: "http://127.0.0.1:" + port, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if outcome, _ := plain.Deposit(context.Background(), envelope); outcome.Accepted() {
		t.Fatal("plain HTTP to the TLS listener was accepted")
	}
}

func selfSigned(t *testing.T, dir string) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}
