package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/messenger/pkg/localapi"
)

func TestOfflineSignProducesBoundDecision(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	request := localapi.Request{
		Schema: localapi.RequestSchema, Op: localapi.OpGrantAction,
		ActionID: "act_" + strings.Repeat("a", 64), Challenge: strings.Repeat("b", 64),
	}
	preimage, err := localapi.DecisionBytes(request, request.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	envelope := decisionEnvelope{Schema: decisionSchema, Request: request, SigningBytesHex: hex.EncodeToString(preimage)}
	directory := t.TempDir()
	decisionPath := filepath.Join(directory, "decision.json")
	keyPath := filepath.Join(directory, "owner.key")
	raw, _ := json.Marshal(envelope)
	if err := os.WriteFile(decisionPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"sign", "-key", keyPath, "-decision", decisionPath}, nil, &output); err != nil {
		t.Fatal(err)
	}
	var signed decisionEnvelope
	if err := json.Unmarshal(output.Bytes(), &signed); err != nil {
		t.Fatal(err)
	}
	signature, err := hex.DecodeString(signed.Request.OwnerSignature)
	if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), preimage, signature) {
		t.Fatal("offline signature does not authorize the exact decision")
	}
}

func TestOfflineSignRejectsLooseKeyAndTamperedDecision(t *testing.T) {
	directory := t.TempDir()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	keyPath := filepath.Join(directory, "owner.key")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPrivateKey(keyPath); err == nil {
		t.Fatal("world-readable owner key accepted")
	}
	envelope := decisionEnvelope{
		Schema:          decisionSchema,
		Request:         localapi.Request{Op: localapi.OpDenyAction, ActionID: "act_" + strings.Repeat("c", 64), Challenge: strings.Repeat("d", 64), Reason: "no"},
		SigningBytesHex: "00",
	}
	if err := validateEnvelope(envelope, false); err == nil {
		t.Fatal("tampered signing preimage accepted")
	}
}

// The invite token is read only from a private file or standard input, never
// from the command line.
func TestInviteTokenComesFromAPrivateFileOrStdin(t *testing.T) {
	directory := t.TempDir()
	token := "invite_" + strings.Repeat("A", 43)
	private := filepath.Join(directory, "token")
	if err := os.WriteFile(private, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if read, err := readToken(private, nil); err != nil || read != token {
		t.Fatalf("private token file: %q %v", read, err)
	}
	loose := filepath.Join(directory, "loose")
	if err := os.WriteFile(loose, []byte(token), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(loose, nil); err == nil {
		t.Fatal("a world-readable token file was accepted")
	}
	if read, err := readToken("-", strings.NewReader(token+"\n")); err != nil || read != token {
		t.Fatalf("token on standard input: %q %v", read, err)
	}
	for _, bad := range []string{"", "two\nlines", strings.Repeat("x", maxTokenBytes+1)} {
		if _, err := readToken("-", strings.NewReader(bad)); err == nil {
			t.Fatalf("token %q accepted", bad)
		}
	}
	if err := run([]string{"-socket", "/nonexistent.sock", "prepare-present-invite", "-recipient", "agent_" + strings.Repeat("a", 64),
		"-token", token, "-expires-at", "1900000000"}, nil, &bytes.Buffer{}); err == nil {
		t.Fatal("a token on the command line was accepted")
	}
}

// -out writes a new mode-0600 file and refuses to overwrite one.
func TestOutputFileIsPrivateAndNew(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	request := localapi.Request{Schema: localapi.RequestSchema, Op: localapi.OpGrantAction,
		ActionID: "act_" + strings.Repeat("a", 64), Challenge: strings.Repeat("b", 64)}
	preimage, err := localapi.DecisionBytes(request, request.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	decisionPath := filepath.Join(directory, "decision.json")
	keyPath := filepath.Join(directory, "owner.key")
	raw, _ := json.Marshal(decisionEnvelope{Schema: decisionSchema, Request: request, SigningBytesHex: hex.EncodeToString(preimage)})
	if err := os.WriteFile(decisionPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signedPath := filepath.Join(directory, "signed.json")
	var stdout bytes.Buffer
	if err := run([]string{"-out", signedPath, "sign", "-key", keyPath, "-decision", decisionPath}, nil, &stdout); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(signedPath)
	if err != nil || info.Mode().Perm() != 0o600 || stdout.Len() != 0 {
		t.Fatalf("signed output: %v %v stdout=%d", info, err, stdout.Len())
	}
	if err := run([]string{"-out", signedPath, "sign", "-key", keyPath, "-decision", decisionPath}, nil, &stdout); err == nil {
		t.Fatal("an existing output file was overwritten")
	}
	failed := filepath.Join(directory, "failed.json")
	if err := run([]string{"-out", failed, "sign", "-key", keyPath, "-decision", signedPath}, nil, &stdout); err == nil {
		t.Fatal("signing a signed decision succeeded")
	}
	if _, err := os.Stat(failed); !os.IsNotExist(err) {
		t.Fatal("a failed command left its output file")
	}
}
