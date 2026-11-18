package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/servicefixture"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/railwork"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestReadSignedActionIsStrictAndRequiresAuthoritySignature(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "signed.json")
	signature := &nativev1.SignatureV1{KeyId: "mldsa44:" + strings.Repeat("11", 32), Mldsa44Signature: make([]byte, 2420)}
	value := &nativev1.SignedNativeActionV1{Action: &nativev1.NativeActionV1{Protocol: "test"},
		AuthoritySignatures: []*nativev1.SignatureV1{signature}}
	raw, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := readSignedAction(path)
	if err != nil || parsed.GetAction().GetProtocol() != "test" || len(parsed.GetAuthoritySignatures()) != 1 {
		t.Fatalf("read signed action: %+v %v", parsed, err)
	}
	if err := os.WriteFile(path, append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSignedAction(path); err == nil {
		t.Fatal("unknown signed action field was accepted")
	}
	// The Registry admits at most 8 signatures; a ninth is refused here.
	for count, accepted := range map[int]bool{8: true, 9: false} {
		value.AuthoritySignatures = nil
		for range count {
			value.AuthoritySignatures = append(value.AuthoritySignatures, signature)
		}
		raw, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readSignedAction(path); (err == nil) != accepted {
			t.Fatalf("%d signatures: accepted = %v", count, err == nil)
		}
	}
}

func TestPublicationNonceAndPrivateTokenFailClosed(t *testing.T) {
	if _, err := nonce(strings.Repeat("0", 64)); err == nil {
		t.Fatal("zero publication nonce was accepted")
	}
	if _, err := nonce(strings.Repeat("A", 64)); err == nil {
		t.Fatal("noncanonical publication nonce was accepted")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "token")
	if err := os.WriteFile(path, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(path); err == nil {
		t.Fatal("public Gateway bearer token file was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if token, err := readToken(path); err != nil || token != "secret" {
		t.Fatalf("private token: %q %v", token, err)
	}
}

func TestStateDirectoryMustBeOwnerPrivateAndNotASymlink(t *testing.T) {
	base := t.TempDir()
	fresh := filepath.Join(base, "fresh")
	if _, err := openJournal(fresh); err != nil {
		t.Fatalf("fresh state directory: %v", err)
	}
	for _, directory := range []string{fresh, filepath.Join(fresh, "journal")} {
		info, err := os.Lstat(directory)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("%s was not created owner-private: %v %v", directory, info, err)
		}
	}
	broad := filepath.Join(base, "broad")
	if err := os.Mkdir(broad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(broad, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openJournal(broad); err == nil {
		t.Fatal("world-readable state directory was used")
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(fresh, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openJournal(link); err == nil {
		t.Fatal("symlinked state directory was used")
	}
	if err := os.Chmod(filepath.Join(fresh, "journal"), 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := openJournal(fresh); err == nil {
		t.Fatal("group-accessible journal directory was used")
	}
	if _, err := openJournal("relative"); err == nil {
		t.Fatal("relative state directory was used")
	}
}

func TestCommandFlagsFailClosed(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	base := []string{"--state-dir", state, "--gateway", "https://gateway.example", "--caller-id", "caller"}
	prepareBase := append(append([]string(nil), base...), "--network-id", "n", "--genesis-root", "r", "--genesis-file", "f",
		"--registry-code-hash", "h", "--owner-agent-id", "agent_"+strings.Repeat("ab", 32), "--manifest-json", "/manifest.json")
	cases := map[string][]string{
		"unknown mode":              {"publish", "--state-dir", state},
		"no state dir":              {"status"},
		"positional argument":       {"status", "--state-dir", state, "extra"},
		"apply without hash":        append([]string{"apply"}, base...),
		"preview without hash":      append([]string{"preview"}, base...),
		"prepare without owner":     append([]string{"prepare"}, base...),
		"rpc without pinned actor":  append(append([]string{"prepare"}, prepareBase...), "--rpc", "http://a,http://b,http://c"),
		"registry code without rpc": append(append([]string{"prepare"}, prepareBase...), "--registry-code-boc", "/registry.boc"),
		"quorum without rpc":        append(append([]string{"prepare"}, prepareBase...), "--quorum", "2"),
		"apply takes no manifest":   append(append([]string{"apply"}, base...), "--action-hash", "sha256:"+strings.Repeat("11", 32), "--manifest-json", "/m.json"),
	}
	for name, arguments := range cases {
		if err := run(arguments, io.Discard, io.Discard); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if err := run([]string{"status", "--state-dir", state, "--action-hash", "sha256:" + strings.Repeat("11", 32)}, io.Discard, io.Discard); err == nil {
		t.Fatal("status of an unjournaled publication succeeded")
	}
	var out strings.Builder
	if err := run([]string{"status", "--state-dir", state}, &out, io.Discard); err != nil || out.Len() != 0 {
		t.Fatalf("status of an empty journal: %q %v", out.String(), err)
	}
}

// A Capability version quoted over Agent Packets is held to the rail task's
// package bound at publication: prepare refuses a manifest whose Quotes no
// task could carry before anything is journaled, and prepares the fixture
// manifest (SERVICE_ACTOR_RAIL_WORK_FRAMES_V1 section 5.1).
func TestPrepareRefusesAnUncarriableManifestForAgentPackets(t *testing.T) {
	tosctl, digest := os.Getenv("TOS_SERVICE_TOSCTL"), os.Getenv("TOS_SERVICE_TOSCTL_SHA256")
	if tosctl == "" || digest == "" {
		t.Fatal("TOS_SERVICE_TOSCTL and TOS_SERVICE_TOSCTL_SHA256 must name the tosctl helper and its SHA-256")
	}
	directory := t.TempDir()
	token := filepath.Join(directory, "token")
	if err := os.WriteFile(token, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	owner := "agent_" + strings.Repeat("ab", 32)
	writeManifest := func(name string, edit func(*nativecore.SoftwareWorkManifestV1)) string {
		manifest := servicefixture.Manifest("1.0.0", servicefixture.DefaultSettlement())
		edit(&manifest)
		raw, err := json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, name)
		if err = os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	fixture := writeManifest("fixture.json", func(*nativecore.SoftwareWorkManifestV1) {})
	large := writeManifest("large.json", func(m *nativecore.SoftwareWorkManifestV1) {
		m.Description = strings.Repeat("d", 2048)
		m.Invocation.Arguments = nil
		for index := 0; index < 64; index++ {
			m.Invocation.Arguments = append(m.Invocation.Arguments, fmt.Sprintf("%02d%s", index, strings.Repeat("a", 510)))
		}
	})
	prepare := func(state, manifest string, extra ...string) error {
		arguments := []string{"prepare", "--state-dir", state, "--gateway", "http://127.0.0.1:9", "--insecure",
			"--token-file", token, "--caller-id", "caller", "--tosctl", tosctl, "--tosctl-sha256", digest,
			"--network-id", "test", "--genesis-root", "sha256:" + strings.Repeat("11", 32),
			"--genesis-file", "sha256:" + strings.Repeat("22", 32),
			"--registry-code-hash", "tvm-cell-sha256:" + strings.Repeat("33", 32),
			"--owner-agent-id", owner, "--manifest-json", manifest}
		return run(append(arguments, extra...), io.Discard, io.Discard)
	}
	agentPackets := []string{"--agent-packet-max-request-bytes", "1048576"}
	refused := filepath.Join(directory, "refused")
	if err := prepare(refused, large, agentPackets...); !errors.Is(err, railwork.ErrQuoteNotCarriable) {
		t.Fatalf("an uncarriable manifest was prepared for Agent Packets: %v", err)
	}
	var out strings.Builder
	if err := run([]string{"status", "--state-dir", refused}, &out, io.Discard); err != nil || out.Len() != 0 {
		t.Fatalf("a refused manifest left a journaled publication: %q %v", out.String(), err)
	}
	if err := prepare(filepath.Join(directory, "fixture"), fixture, agentPackets...); err != nil {
		t.Fatalf("a carriable manifest was refused: %v", err)
	}
	if err := prepare(filepath.Join(directory, "https"), large); err != nil {
		t.Fatalf("a manifest not quoted over Agent Packets was held to the rail bound: %v", err)
	}
	if err := prepare(filepath.Join(directory, "over"), fixture, "--agent-packet-max-request-bytes", "1048577"); err == nil {
		t.Fatal("an Agent Packet inline bound over 1 MiB was accepted")
	}
}
