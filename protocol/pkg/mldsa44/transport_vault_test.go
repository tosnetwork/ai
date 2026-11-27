package mldsa44

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func vaultTable(name string) []byte {
	return []byte("ID Algorithm Payload Extractable Created\n------\n" + name + " Ed25519 KeyPair No 2026-11-27 12:00 " + base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)) + "\n")
}
func TestTransportVaultTableRefusals(t *testing.T) {
	raw := vaultTable("transport-key")
	if _, err := parseTransportPublic(raw, "transport-key"); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{"extractable": bytes.ReplaceAll(raw, []byte(" No "), []byte(" Yes ")), "algorithm": bytes.ReplaceAll(raw, []byte("Ed25519"), []byte("None")), "name": bytes.ReplaceAll(raw, []byte("transport-key"), []byte("other")), "extra-row": append(bytes.Clone(raw), raw...), "missing": nil, "key": bytes.ReplaceAll(raw, []byte("="), []byte("!"))} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseTransportPublic(bad, "transport-key"); err == nil {
				t.Fatal("invalid key metadata accepted")
			}
		})
	}
}

// This lane is intentionally required, like the existing real controller
// custody tests: a missing helper is an error, not a skipped acceptance test.
func TestTransportVaultRealCustody(t *testing.T) {
	binary := os.Getenv("TOS_SERVICE_VAULT_HELPER")
	if binary == "" {
		binary = filepath.Join(filepath.Dir(os.Getenv("TOS_SERVICE_TOSCTL")), "secrets-vault-cli")
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal("TOS_SERVICE_VAULT_HELPER must name the existing secrets-vault-cli build:", err)
	}
	digest := sha256.Sum256(raw)
	dir, err := os.MkdirTemp("", "transport-vault-custody-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	if err = os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	master := make([]byte, 32)
	if _, err = rand.Read(master); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "vault.json")
	vault, err := NewTransportVault(binary, hex.EncodeToString(digest[:]), "file://"+path+"?master_key="+hex.EncodeToString(master))
	if err != nil {
		t.Fatal(err)
	}
	key, err := vault.EnsureKey(t.Context(), "transport-key")
	if err != nil {
		t.Fatal(err)
	}
	again, err := vault.EnsureKey(t.Context(), "transport-key")
	if err != nil || key != again || key == [32]byte{} {
		t.Fatalf("rerun %x %v", again, err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("vault mode %v %v", info, err)
	}
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte(hex.EncodeToString(master))) {
		t.Fatal("vault master key leaked to disk")
	}
	// Existing metadata is not silently upgraded or replaced: an extractable
	// key with the requested name is refused, even if it is otherwise Ed25519.
	if _, err = vault.run(context.Background(), "generate", "--secret-id", "extractable", "--algorithm", "Ed25519", "--extractable"); err != nil {
		t.Fatal(err)
	}
	if _, err = vault.EnsureKey(t.Context(), "extractable"); err == nil {
		t.Fatal("extractable key accepted")
	}
	if _, err = vault.EnsureKey(t.Context(), strings.Repeat("x", 31)); err == nil {
		t.Fatal("truncated name accepted")
	}
	if _, err = NewTransportVault(binary, fmt.Sprintf("%064d", 0), "file://unused"); err == nil {
		t.Fatal("wrong binary pin accepted")
	}
}
