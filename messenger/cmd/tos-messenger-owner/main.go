// Command tos-messenger-owner operates the owner-only approval boundary.
// It separates online challenge acquisition/submission from signing so the
// private key can remain on an isolated machine or be replaced by a hardware
// signer without changing the daemon protocol.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tosnetwork/ai/messenger/internal/osguard"
	"github.com/tosnetwork/ai/messenger/internal/securefile"
	"github.com/tosnetwork/ai/messenger/pkg/localapi"
)

// decisionSchema names the offline-signing envelope. v2 matches the request
// layout without mandate fields, so a v1 envelope prepared by an older tool
// is refused rather than signed against a different preimage.
const decisionSchema = "tos.messaging.owner-decision.v2"

type decisionEnvelope struct {
	Schema          string           `json:"schema"`
	Request         localapi.Request `json:"request"`
	SigningBytesHex string           `json:"signing_bytes_hex"`
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "tos-messenger-owner:", err)
		os.Exit(1)
	}
}

func run(args []string, input io.Reader, stdout io.Writer) error {
	global := flag.NewFlagSet("tos-messenger-owner", flag.ContinueOnError)
	global.SetOutput(io.Discard)
	socket := global.String("socket", "", "clean absolute owner socket path")
	timeout := global.Duration("timeout", localapi.DefaultClientTimeout, "request timeout")
	outPath := global.String("out", "", "write the output to this new file, mode 0600, instead of standard output")
	if err := global.Parse(args); err != nil {
		return err
	}
	rest := global.Args()
	if len(rest) == 0 {
		return errors.New("usage: tos-messenger-owner [-socket PATH] [-out FILE] <pending|history|prepare-grant|prepare-deny|prepare-invite|prepare-present-invite|prepare-remove-contact|prepare-history|sign|submit>")
	}
	// A prepared or signed decision can carry a bearer (a presented invite
	// token), so -out writes a new private file rather than relying on the
	// caller's umask for a shell redirection.
	output, finish, err := openOutput(*outPath, stdout)
	if err != nil {
		return err
	}
	if err := dispatchCommand(rest, *socket, *timeout, input, output); err != nil {
		finish(false)
		return err
	}
	return finish(true)
}

func dispatchCommand(rest []string, socketPath string, timeout time.Duration, input io.Reader, output io.Writer) error {
	socket := &socketPath
	if rest[0] == "sign" {
		return signCommand(rest[1:], output)
	}
	client, err := localapi.NewClient(*socket, timeout)
	if err != nil {
		return err
	}
	switch rest[0] {
	case "pending":
		set := commandFlags("pending")
		limit := set.Int("limit", localapi.MaxEventsPerResponse, "maximum actions")
		if err := set.Parse(rest[1:]); err != nil || set.NArg() != 0 {
			return errors.New("usage: pending [-limit N]")
		}
		response, err := client.Call(context.Background(), localapi.Request{Op: localapi.OpPendingActions, Limit: *limit})
		if err != nil {
			return err
		}
		return writeJSON(output, response.Actions)
	case "history":
		set := commandFlags("history")
		conversation := set.String("conversation", "", "direct Conversation identifier")
		limit := set.Int("limit", localapi.MaxHistoryEventsPerResponse, "maximum recent display Events")
		if err := set.Parse(rest[1:]); err != nil || set.NArg() != 0 || *conversation == "" {
			return errors.New("usage: history -conversation CONV_ID [-limit N]")
		}
		response, err := client.Call(context.Background(), localapi.Request{
			Op: localapi.OpListDeviceHistory, ConversationID: *conversation, Limit: *limit,
		})
		if err != nil {
			return err
		}
		return writeJSON(output, response.History)
	case "prepare-grant":
		if len(rest) != 2 {
			return errors.New("usage: prepare-grant ACTION_ID")
		}
		return prepare(client, localapi.Request{Op: localapi.OpGrantAction, ActionID: rest[1]}, output)
	case "prepare-deny":
		set := commandFlags("prepare-deny")
		reason := set.String("reason", "", "owner-visible refusal reason")
		if err := set.Parse(rest[1:]); err != nil || set.NArg() != 1 || *reason == "" {
			return errors.New("usage: prepare-deny -reason TEXT ACTION_ID")
		}
		return prepare(client, localapi.Request{Op: localapi.OpDenyAction, ActionID: set.Arg(0), Reason: *reason}, output)
	case "prepare-invite":
		set := commandFlags("prepare-invite")
		agentID := set.String("agent", "", "optional Agent identifier allowed to spend the invite")
		expiresAt := set.Uint64("expires-at", 0, "absolute Unix expiry (maximum 30 days)")
		if err := set.Parse(rest[1:]); err != nil || set.NArg() != 0 || *expiresAt == 0 {
			return errors.New("usage: prepare-invite -expires-at UNIX [-agent AGENT_ID]")
		}
		return prepare(client, localapi.Request{
			Op: localapi.OpCreateAdmissionInvite, InvitedAgentID: *agentID, InviteExpiresAtUnix: *expiresAt,
		}, output)
	case "prepare-present-invite":
		set := commandFlags("prepare-present-invite")
		recipient := set.String("recipient", "", "Agent whose owner issued the invite")
		tokenFile := set.String("token-file", "", "0600 file holding the invite_ token, or - for standard input")
		expiresAt := set.Uint64("expires-at", 0, "the invite's absolute Unix expiry")
		if err := set.Parse(rest[1:]); err != nil || set.NArg() != 0 || *recipient == "" || *tokenFile == "" || *expiresAt == 0 {
			return errors.New("usage: prepare-present-invite -recipient AGENT_ID -token-file FILE|- -expires-at UNIX")
		}
		// The token is a bearer: it is never taken from the command line,
		// where other local users can read it.
		token, err := readToken(*tokenFile, input)
		if err != nil {
			return err
		}
		return prepare(client, localapi.Request{
			Op: localapi.OpPresentInvite, InviteRecipientAgentID: *recipient, InviteToken: token, InviteExpiresAtUnix: *expiresAt,
		}, output)
	case "prepare-remove-contact":
		set := commandFlags("prepare-remove-contact")
		agentID := set.String("agent", "", "invited contact to remove")
		if err := set.Parse(rest[1:]); err != nil || set.NArg() != 0 || *agentID == "" {
			return errors.New("usage: prepare-remove-contact -agent AGENT_ID")
		}
		return prepare(client, localapi.Request{Op: localapi.OpRemoveContact, ContactAgentID: *agentID}, output)
	case "prepare-history":
		set := commandFlags("prepare-history")
		target := set.String("target-device", "", "current destination Device identifier")
		conversation := set.String("conversation", "", "direct Conversation identifier")
		sequence := set.Uint64("sequence", 1, "segment sequence starting at one")
		previous := set.String("previous-digest", "", "prior segment sha256 digest")
		afterUnix := set.Uint64("after-unix", 0, "prior page's last Event creation time")
		afterEvent := set.String("after-event", "", "prior page's last Event identifier")
		limit := set.Int("limit", 0, "page size; zero selects the protocol maximum")
		idempotency := set.String("idempotency", "", "unique idem_ identifier for this page")
		expiresAt := set.Uint64("expires-at", 0, "absolute Unix Event expiry")
		if err := set.Parse(rest[1:]); err != nil || set.NArg() != 0 || *target == "" ||
			*conversation == "" || *idempotency == "" || *expiresAt == 0 {
			return errors.New("usage: prepare-history -target-device DEV_ID -conversation CONV_ID -idempotency IDEM_ID -expires-at UNIX [-sequence N -previous-digest DIGEST -after-unix UNIX -after-event EVT_ID -limit N]")
		}
		return prepare(client, localapi.Request{Op: localapi.OpExportDeviceHistory,
			TargetDeviceID: *target, ConversationID: *conversation, HistorySequence: *sequence,
			PreviousSegmentDigest: *previous, AfterCreatedAtUnix: *afterUnix, AfterEventID: *afterEvent,
			Limit: *limit, IdempotencyKey: *idempotency, ExpiresAtUnix: *expiresAt}, output)
	case "submit":
		set := commandFlags("submit")
		path := set.String("decision", "", "signed decision JSON")
		if err := set.Parse(rest[1:]); err != nil || set.NArg() != 0 || *path == "" {
			return errors.New("usage: submit -decision FILE")
		}
		envelope, err := readDecision(*path)
		if err != nil {
			return err
		}
		if err := validateEnvelope(envelope, true); err != nil {
			return err
		}
		response, err := client.Call(context.Background(), envelope.Request)
		if err != nil {
			return err
		}
		return writeJSON(output, response)
	default:
		return errors.New("unknown owner command")
	}
}

func commandFlags(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	return set
}

func prepare(client *localapi.Client, request localapi.Request, output io.Writer) error {
	issued, err := client.Call(context.Background(), localapi.Request{Op: localapi.OpChallenge})
	if err != nil {
		return err
	}
	request.Schema = localapi.RequestSchema
	request.Challenge = issued.Challenge
	preimage, err := localapi.DecisionBytes(request, issued.Challenge)
	if err != nil {
		return err
	}
	return writeJSON(output, decisionEnvelope{Schema: decisionSchema, Request: request, SigningBytesHex: hex.EncodeToString(preimage)})
}

func signCommand(args []string, output io.Writer) error {
	set := commandFlags("sign")
	keyPath := set.String("key", "", "0600 Ed25519 private key file containing 128 lowercase hex digits")
	decisionPath := set.String("decision", "", "prepared decision JSON")
	if err := set.Parse(args); err != nil || set.NArg() != 0 || *keyPath == "" || *decisionPath == "" {
		return errors.New("usage: sign -key FILE -decision FILE")
	}
	envelope, err := readDecision(*decisionPath)
	if err != nil {
		return err
	}
	if err := validateEnvelope(envelope, false); err != nil {
		return err
	}
	key, err := readPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	defer clear(key)
	signature, err := localapi.SignDecision(envelope.Request, envelope.Request.Challenge, key)
	if err != nil {
		return err
	}
	envelope.Request.OwnerSignature = signature
	return writeJSON(output, envelope)
}

func validateEnvelope(envelope decisionEnvelope, signed bool) error {
	if envelope.Schema != decisionSchema || !localapi.Deciding(envelope.Request.Op) {
		return errors.New("unsupported owner decision")
	}
	preimage, err := localapi.DecisionBytes(envelope.Request, envelope.Request.Challenge)
	if err != nil || envelope.SigningBytesHex != hex.EncodeToString(preimage) {
		return errors.New("owner decision signing bytes do not match its request")
	}
	if signed {
		raw, err := hex.DecodeString(envelope.Request.OwnerSignature)
		if err != nil || len(raw) != ed25519.SignatureSize || envelope.Request.OwnerSignature != strings.ToLower(envelope.Request.OwnerSignature) {
			return errors.New("owner decision has no canonical Ed25519 signature")
		}
	} else if envelope.Request.OwnerSignature != "" {
		return errors.New("prepared owner decision is already signed")
	}
	return nil
}

func readDecision(path string) (decisionEnvelope, error) {
	raw, err := readRegular(path, 64<<10, false)
	if err != nil {
		return decisionEnvelope{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var envelope decisionEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return decisionEnvelope{}, errors.New("decode owner decision")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return decisionEnvelope{}, errors.New("owner decision has trailing JSON")
	}
	return envelope, nil
}

// maxTokenBytes bounds an invite token file: the token and a newline.
const maxTokenBytes = 128

// readToken reads an invite token from a private file (mode 0600, owned by
// this user) or, for "-", from standard input.
func readToken(path string, input io.Reader) (string, error) {
	var raw []byte
	if path == "-" {
		if input == nil {
			return "", errors.New("no standard input for the invite token")
		}
		read, err := io.ReadAll(io.LimitReader(input, maxTokenBytes+1))
		if err != nil {
			return "", errors.New("read the invite token")
		}
		raw = read
	} else {
		read, err := readRegular(path, maxTokenBytes, true)
		if err != nil {
			return "", err
		}
		raw = read
	}
	if len(raw) > maxTokenBytes {
		return "", errors.New("invite token exceeds its bound")
	}
	token := strings.TrimSuffix(string(raw), "\n")
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", errors.New("invite token must be one line")
	}
	return token, nil
}

// openOutput returns standard output, or a new mode-0600 file that finish
// syncs and closes, or removes when the command failed.
func openOutput(path string, stdout io.Writer) (io.Writer, func(bool) error, error) {
	if path == "" {
		return stdout, func(bool) error { return nil }, nil
	}
	if filepath.Clean(path) != path {
		return nil, nil, errors.New("output path must be clean")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, nil, errors.New("create the output file (it must not exist)")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, nil, errors.New("protect the output file")
	}
	finish := func(ok bool) error {
		if !ok {
			_ = file.Close()
			_ = os.Remove(path)
			return nil
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return errors.New("sync the output file")
		}
		if err := file.Close(); err != nil {
			_ = os.Remove(path)
			return errors.New("close the output file")
		}
		return nil
	}
	return file, finish, nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := readRegular(path, 130, true)
	if err != nil {
		return nil, err
	}
	text := strings.TrimSuffix(string(raw), "\n")
	if len(text) != ed25519.PrivateKeySize*2 || text != strings.ToLower(text) {
		return nil, errors.New("owner key must be 128 lowercase hex digits")
	}
	decoded, err := hex.DecodeString(text)
	if err != nil {
		return nil, errors.New("decode owner key")
	}
	key := ed25519.PrivateKey(decoded)
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if !bytes.Equal(derived, key) {
		clear(key)
		return nil, errors.New("owner private key has an inconsistent public half")
	}
	return key, nil
}

func readRegular(path string, maximum int64, secret bool) ([]byte, error) {
	raw, info, err := securefile.ReadBoundedRegularInfo(path, maximum)
	if err != nil {
		return nil, err
	}
	if secret {
		// The owner and mode are those of the file that was opened and read,
		// not of whatever the path names now.
		if info == nil || !info.Mode().IsRegular() {
			return nil, errors.New("a secret file must remain a regular file")
		}
		if !osguard.CurrentUserOwns(info) || info.Mode().Perm() != 0o600 {
			return nil, errors.New("a secret file must be owned by this user with mode 0600")
		}
	}
	return raw, nil
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
