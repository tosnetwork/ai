package agentpacketrelay

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

// relayVectorPath is the frozen Agent Packet Relay V1 corpus. It is read,
// never written; a missing corpus fails the test.
var relayVectorPath = filepath.Join("..", "..", "..", "spec", "test-vectors", "agent-packet-relay-v1.json")

type corpus struct {
	Keys []struct {
		Name string `json:"name"`
		Seed string `json:"private_key_seed_hex"`
	} `json:"keys"`
	Envelopes []struct {
		Name       string `json:"name"`
		Key        string `json:"key"`
		Recipient  string `json:"recipient_agent_id"`
		AckSecret  string `json:"ack_secret_hex"`
		Expires    uint64 `json:"expires_at_unix"`
		PacketJSON string `json:"packet_json_hex"`
		Envelope   string `json:"envelope_hex"`
	} `json:"envelope_positive"`
	Negatives []struct {
		Name      string `json:"name"`
		Base      string `json:"base"`
		OpenWith  string `json:"open_with_key"`
		OpenAs    string `json:"open_as_agent_id"`
		Rejection string `json:"rejection"`
		Envelope  string `json:"envelope_hex"`
		Mutation  struct {
			Op     string `json:"op"`
			Offset int    `json:"offset"`
			Length int    `json:"length"`
			Hex    string `json:"hex"`
		} `json:"mutation"`
	} `json:"envelope_negative"`
}

func loadCorpus(t *testing.T) corpus {
	t.Helper()
	raw, err := os.ReadFile(relayVectorPath)
	if err != nil {
		t.Fatalf("the frozen corpus is required: %v", err)
	}
	var doc corpus
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Envelopes) != 2 || len(doc.Negatives) != 22 || len(doc.Keys) != 2 {
		t.Fatalf("corpus shape changed: %d positive, %d negative, %d keys", len(doc.Envelopes), len(doc.Negatives), len(doc.Keys))
	}
	return doc
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// relayAt returns a relay whose clock is one hour before expiresAt.
func relayAt(t *testing.T, expiresAt uint64) *testRelay {
	t.Helper()
	store, err := NewMemoryStore(testLimits())
	if err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{now: time.Unix(int64(expiresAt)-3600, 0)}
	return newTestRelayWithStore(t, store, clock)
}

// TestCorpusEnvelopes runs the frozen envelopes through the relay: every
// positive is stored at the mailbox and ID its header names and still opens
// after a download; every negative the corpus classes as malformed or
// unsupported suite is refused with 400; every other negative is a
// well-formed header the relay cannot judge, so it is stored and its
// recipient's Open refuses it.
func TestCorpusEnvelopes(t *testing.T) {
	doc := loadCorpus(t)
	seeds := map[string][]byte{}
	for _, key := range doc.Keys {
		seeds[key.Name] = mustHex(t, key.Seed)
	}
	positives := map[string][]byte{}
	ctx := context.Background()
	for _, vector := range doc.Envelopes {
		envelope := mustHex(t, vector.Envelope)
		positives[vector.Name] = envelope
		relay := relayAt(t, vector.Expires)
		var secret [32]byte
		copy(secret[:], mustHex(t, vector.AckSecret))
		id := agentpacketseal.AckHash(secret)
		expectStatus(t, relay.put(vector.Recipient, id, envelope), http.StatusCreated)
		list, err := relay.client.List(ctx, vector.Recipient)
		if err != nil || len(list.Envelopes) != 1 || list.Envelopes[0].EnvelopeID != id ||
			list.Envelopes[0].ExpiresAtUnix != vector.Expires || int(list.Envelopes[0].Size) != len(envelope) {
			t.Fatalf("%s: list = %+v, %v", vector.Name, list, err)
		}
		downloaded, err := relay.client.Download(ctx, vector.Recipient, id)
		if err != nil || !bytes.Equal(downloaded, envelope) {
			t.Fatalf("%s: download: %v", vector.Name, err)
		}
		key, err := agentpacketseal.NewPrivateKey(vector.Recipient, seeds[vector.Key])
		if err != nil {
			t.Fatal(err)
		}
		opened, err := agentpacketseal.Open(key, downloaded)
		if err != nil || !bytes.Equal(opened.PacketJSON, mustHex(t, vector.PacketJSON)) {
			t.Fatalf("%s: open: %v", vector.Name, err)
		}
		if err := relay.client.Ack(ctx, vector.Recipient, id, opened.AckSecret); err != nil {
			t.Fatalf("%s: ack: %v", vector.Name, err)
		}
	}

	for _, vector := range doc.Negatives {
		t.Run(vector.Name, func(t *testing.T) {
			// A negative is either a mutation of a positive, the positive
			// itself opened under another key or Agent, or a complete
			// envelope sealed for the purpose.
			base := positives[vector.Base]
			if vector.Envelope != "" {
				if vector.Base != "" {
					t.Fatal("negative names both a base and its own envelope")
				}
				base = mustHex(t, vector.Envelope)
			}
			if base == nil {
				t.Fatalf("unknown base %q", vector.Base)
			}
			mutated := append([]byte(nil), base...)
			switch vector.Mutation.Op {
			case "":
			case "xor":
				for index, b := range mustHex(t, vector.Mutation.Hex) {
					mutated[vector.Mutation.Offset+index] ^= b
				}
			case "truncate":
				mutated = mutated[:vector.Mutation.Length]
			case "append":
				mutated = append(mutated, mustHex(t, vector.Mutation.Hex)...)
			default:
				t.Fatalf("unknown mutation %q", vector.Mutation.Op)
			}
			baseHeader, err := agentpacketseal.ParseEnvelope(base)
			if err != nil {
				t.Fatal(err)
			}
			relay := relayAt(t, baseHeader.ExpiresAtUnix)
			header, parseErr := agentpacketseal.ParseEnvelope(mutated)
			switch vector.Rejection {
			case "malformed", "suite":
				if parseErr == nil {
					t.Fatal("the relay parser accepted a corpus envelope classed as malformed")
				}
				expectStatus(t, relay.put(baseHeader.RecipientAgentID, baseHeader.EnvelopeID, mutated), http.StatusBadRequest)
				if outcome, err := relay.client.Deposit(context.Background(), mutated); !errors.Is(err, ErrInvalidArgument) ||
					outcome.Result != 0 {
					t.Fatalf("client sent a malformed envelope: %+v, %v", outcome, err)
				}
				return
			case "recipient", "open", "plaintext", "ack":
			default:
				t.Fatalf("unknown rejection class %q", vector.Rejection)
			}
			if parseErr != nil {
				t.Fatalf("a well-formed header was refused by the relay parser: %v", parseErr)
			}
			if header.RecipientAgentID != baseHeader.RecipientAgentID || header.EnvelopeID != baseHeader.EnvelopeID {
				// The mutation moved the header off the base path: the
				// base path refuses it.
				expectStatus(t, relay.put(baseHeader.RecipientAgentID, baseHeader.EnvelopeID, mutated), http.StatusBadRequest)
			}
			outcome, err := relay.client.Deposit(context.Background(), mutated)
			if err != nil || outcome.Result != DepositStored {
				t.Fatalf("deposit at its own header path = %+v, %v", outcome, err)
			}
			downloaded, err := relay.client.Download(context.Background(), header.RecipientAgentID, header.EnvelopeID)
			if err != nil || !bytes.Equal(downloaded, mutated) {
				t.Fatalf("download: %v", err)
			}
			key, err := agentpacketseal.NewPrivateKey(vector.OpenAs, seeds[vector.OpenWith])
			if err != nil {
				t.Fatal(err)
			}
			if _, err := agentpacketseal.Open(key, downloaded); err == nil {
				t.Fatal("the recipient opened a corpus negative")
			}
		})
	}
}
