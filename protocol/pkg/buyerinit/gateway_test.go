package buyerinit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gatewayFiles writes a CA file holding one self-signed certificate and a
// 0600 token file into directory.
func gatewayFiles(t *testing.T, directory string) (caFile, tokenFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway test CA"},
		NotBefore: time.Unix(1_700_000_000, 0), NotAfter: time.Unix(2_000_000_000, 0), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	caFile, tokenFile = filepath.Join(directory, "gateway-ca.pem"), filepath.Join(directory, "gateway.token")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("relay-token-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return caFile, tokenFile
}

func TestInitGatewayInputFollowsTheAgentsRules(t *testing.T) {
	w := newWorld(t)
	valid := w.input(t)
	valid.GatewayURL, valid.GatewayCAFile, valid.GatewayTokenFile = "https://gateway.example", "/srv/ca.pem", "/srv/token"
	isolated(t, func() {
		for name, mutate := range map[string]func(*Input){
			"an unparsable gateway":      func(in *Input) { in.GatewayURL = "https://gate way" },
			"no gateway host":            func(in *Input) { in.GatewayURL = "https:///" },
			"an opaque gateway":          func(in *Input) { in.GatewayURL = "https:gateway.example" },
			"a non-canonical gateway":    func(in *Input) { in.GatewayURL = "HTTPS://gateway.example" },
			"an escaped gateway path":    func(in *Input) { in.GatewayURL = "https://gateway.example:443/%7e" },
			"a CA alone with no gateway": func(in *Input) { in.GatewayURL, in.GatewayTokenFile = "", "" },
		} {
			in := valid
			mutate(&in)
			if err := checkInput(in); err == nil {
				t.Errorf("%s was accepted", name)
			}
		}
	})
	for name, mutate := range map[string]func(*Input){
		"a CA without a gateway":       func(in *Input) { in.GatewayURL = "" },
		"a token without a gateway":    func(in *Input) { in.GatewayURL, in.GatewayCAFile = "", "" },
		"an https gateway with no CA":  func(in *Input) { in.GatewayCAFile = "" },
		"a non-loopback http gateway":  func(in *Input) { in.GatewayURL, in.GatewayCAFile = "http://gateway.example", "" },
		"a non-loopback http address":  func(in *Input) { in.GatewayURL, in.GatewayCAFile = "http://10.0.0.1:8443", "" },
		"a CA for a plaintext gateway": func(in *Input) { in.GatewayURL = "http://127.0.0.1:8443" },
		"another scheme":               func(in *Input) { in.GatewayURL = "ftp://gateway.example" },
		"a gateway path":               func(in *Input) { in.GatewayURL = "https://gateway.example/v1" },
		"a gateway query":              func(in *Input) { in.GatewayURL = "https://gateway.example?x=1" },
		"a gateway fragment":           func(in *Input) { in.GatewayURL = "https://gateway.example#x" },
		"gateway credentials":          func(in *Input) { in.GatewayURL = "https://user@gateway.example" },
		"no token file":                func(in *Input) { in.GatewayTokenFile = "" },
		"a relative token file":        func(in *Input) { in.GatewayTokenFile = "token" },
		"a relative gateway CA":        func(in *Input) { in.GatewayCAFile = "ca.pem" },
		"a relative catalog":           func(in *Input) { in.CatalogDir = "catalog" },
		"an unclean catalog":           func(in *Input) { in.CatalogDir = "/srv/catalog/" },
	} {
		in := valid
		mutate(&in)
		if err := checkInput(in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if err := checkInput(valid); err != nil {
		t.Fatalf("an https gateway with its CA and token: %v", err)
	}
	for _, loopback := range []string{"http://127.0.0.1:8443", "http://localhost:8443", "http://[::1]:8443"} {
		in := valid
		in.GatewayURL, in.GatewayCAFile = loopback, ""
		if err := checkInput(in); err != nil {
			t.Errorf("a loopback http gateway %s with no CA: %v", loopback, err)
		}
	}
	in := valid
	in.CatalogDir = "/srv/catalog"
	if err := checkInput(in); err != nil {
		t.Fatalf("a catalog: %v", err)
	}
}

func TestInitWritesTheGatewayAndCatalogItChecked(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	in.GatewayURL = "https://gateway.example"
	in.GatewayCAFile, in.GatewayTokenFile = gatewayFiles(t, filepath.Dir(in.ConfigPath))
	in.CatalogDir = filepath.Join(filepath.Dir(in.ConfigPath), "catalog")
	if err := Check(in, 4242); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(context.Background(), in, w.env(true)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(in.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	config, err := DecodeAgentConfig(raw)
	if err != nil || config.GatewayURL != in.GatewayURL || config.GatewayCAFile != in.GatewayCAFile ||
		config.GatewayTokenFile != in.GatewayTokenFile || config.CatalogDir != in.CatalogDir {
		t.Fatalf("config %+v %v", config, err)
	}
}

func TestInitRefusesGatewayFilesTheAgentCouldNotUse(t *testing.T) {
	w := newWorld(t)
	in := w.input(t)
	directory := filepath.Dir(in.ConfigPath)
	in.GatewayURL = "https://gateway.example"
	in.GatewayCAFile, in.GatewayTokenFile = gatewayFiles(t, directory)
	write := func(path, content string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	original, err := os.ReadFile(in.GatewayCAFile)
	if err != nil {
		t.Fatal(err)
	}
	for name, corrupt := range map[string]func(){
		"a token others can read": func() { write(in.GatewayTokenFile, "token\n", 0o644) },
		"an empty token":          func() { write(in.GatewayTokenFile, "\n", 0o600) },
		"a token with a space":    func() { write(in.GatewayTokenFile, "two words\n", 0o600) },
		"a non-ASCII token":       func() { write(in.GatewayTokenFile, "t\xc3\xb6ken\n", 0o600) },
		"a token over 4096 bytes": func() { write(in.GatewayTokenFile, strings.Repeat("a", 4097), 0o600) },
		"no token file":           func() { in.GatewayTokenFile = filepath.Join(directory, "absent.token") },
		"a CA with no certificate": func() {
			write(in.GatewayCAFile, "not a certificate\n", 0o644)
		},
		"a CA that is a directory": func() { in.GatewayCAFile = directory },
	} {
		corrupt()
		if err := Check(in, 4242); err == nil {
			t.Errorf("%s was accepted", name)
		}
		if _, err := Plan(context.Background(), in, w.env(true)); err == nil {
			t.Errorf("a plan accepted %s", name)
		}
		in.GatewayCAFile, in.GatewayTokenFile = filepath.Join(directory, "gateway-ca.pem"), filepath.Join(directory, "gateway.token")
		write(in.GatewayTokenFile, "relay-token-1\n", 0o600)
		write(in.GatewayCAFile, string(original), 0o644)
	}
	if err := Check(in, 4242); err != nil {
		t.Fatalf("the restored files: %v", err)
	}
	// A loopback http gateway needs a token but no CA.
	in.GatewayURL, in.GatewayCAFile = "http://127.0.0.1:8443", ""
	if err := Check(in, 4242); err != nil {
		t.Fatalf("a loopback http gateway: %v", err)
	}
}
