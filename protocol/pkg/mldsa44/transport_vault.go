package mldsa44

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// TransportVault uses the existing vault CLI and encrypted key store. Only
// a public key crosses this boundary; the generated key is not extractable.
// The caller must serialize creation under its operation journal lock.
type TransportVault struct {
	snapshot *executableSnapshot
	vaultURL string
}

func NewTransportVault(binary, pin, vaultURL string) (*TransportVault, error) {
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary || !sha256HexPattern.MatchString(pin) || vaultURL == "" || strings.ContainsAny(vaultURL, "\x00\n") {
		return nil, errors.New("invalid transport vault configuration")
	}
	snapshot, err := pinExecutable(binary, pin)
	if err != nil {
		return nil, err
	}
	return &TransportVault{snapshot, vaultURL}, nil
}

// EnsureKey resumes after a crash during generation by reading the same vault
// record. Generate uses the vault's NewOnly operation, never overwrite.
func (v *TransportVault) EnsureKey(ctx context.Context, name string) ([32]byte, error) {
	if ctx == nil || v == nil || v.snapshot == nil {
		return [32]byte{}, errors.New("transport vault and context required")
	}
	if !controllerNamePattern.MatchString(name) || len(name) > 30 {
		return [32]byte{}, errors.New("transport key name must be 1..30 canonical characters")
	}
	raw, err := v.run(ctx, "get", "--secret-id", name)
	if err == nil {
		return parseTransportPublic(raw, name)
	}
	if _, err := v.run(ctx, "generate", "--secret-id", name, "--algorithm", "Ed25519"); err != nil {
		// A previous invocation may have committed before it stopped, or a parallel
		// NewOnly create may have won. Never infer absence from a helper failure.
		raw, readErr := v.run(ctx, "get", "--secret-id", name)
		if readErr != nil {
			return [32]byte{}, errors.New("transport vault create/read refused")
		}
		return parseTransportPublic(raw, name)
	}
	raw, err = v.run(ctx, "get", "--secret-id", name)
	if err != nil {
		return [32]byte{}, errors.New("transport vault read refused")
	}
	return parseTransportPublic(raw, name)
}

func parseTransportPublic(raw []byte, name string) ([32]byte, error) {
	var key [32]byte
	// Existing CLI has a two-line table header. Require exactly one complete
	// non-extractable Ed25519 record; never accept an unrelated row or ANSI text.
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		return key, errors.New("invalid transport vault public-key table")
	}
	fields := strings.Fields(lines[2])
	if len(fields) != 7 || fields[0] != name || fields[1] != "Ed25519" || fields[2] != "KeyPair" || fields[3] != "No" {
		return key, errors.New("transport vault key must be non-extractable Ed25519")
	}
	pk, err := base64.StdEncoding.Strict().DecodeString(fields[6])
	if err != nil || len(pk) != len(key) || base64.StdEncoding.EncodeToString(pk) != fields[6] {
		return key, errors.New("invalid transport vault public key")
	}
	copy(key[:], pk)
	return key, nil
}

func (v *TransportVault) run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultHelperTimeout)
	defer cancel()
	file, err := v.snapshot.executable()
	if err != nil {
		return nil, err
	}
	// The sealed snapshot is shared; ExtraFiles duplicates it for the child.
	command := exec.CommandContext(ctx, "/proc/self/fd/3", args...)
	command.Dir = "/"
	command.ExtraFiles = []*os.File{file}
	command.Env = []string{"VAULT_URL=" + v.vaultURL, "NO_COLOR=1"}
	command.WaitDelay = 5 * time.Second
	out, stderr := &limitedBuffer{limit: maxHelperStdout}, &limitedBuffer{limit: maxHelperStderr}
	command.Stdout, command.Stderr = out, stderr
	if err := command.Run(); err != nil {
		return nil, errors.New("transport vault helper refused")
	}
	if out.overflow || stderr.overflow {
		return nil, errors.New("transport vault output exceeds limit")
	}
	return out.Bytes(), nil
}

// TransportKeys opens the transport-key view of this signer's exact custody
// location without exposing vault credentials to the caller.
func (t *Tosctl) TransportKeys(binary, pin string) (*TransportVault, error) {
	if t == nil || !t.CanSign() {
		return nil, errors.New("controller custody is not configured")
	}
	return NewTransportVault(binary, pin, t.config.VaultURL)
}
