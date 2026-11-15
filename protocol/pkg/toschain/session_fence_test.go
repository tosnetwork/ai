package toschain

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

// fenceChain is a finalized chain whose head the test moves. Every account
// is not active, so a registry read returns "not found" after it has gone
// through the checkpoint fences.
type fenceChain struct {
	head atomic.Uint64
	urls []string
	// stale is the number of consensus answers still to be given as
	// staleHead instead of the head; staleForever answers every one so.
	stale        atomic.Int64
	staleHead    uint64
	staleForever bool
	consensus    atomic.Int64
}

func newFenceChain(t *testing.T, locator *nativecore.Locator, head uint64) *fenceChain {
	t.Helper()
	chain := &fenceChain{}
	chain.head.Store(head)
	genesis := func(value string) string {
		raw, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}
	initRoot, initFile := genesis(locator.Network.GenesisRootHash), genesis(locator.Network.GenesisFileHash)
	block := func(seqno uint64) map[string]any {
		root, file := fenceBlock(seqno)
		return map[string]any{"@type": "tos.blockIdExt", "workchain": -1, "shard": "8000000000000000", "seqno": seqno,
			"root_hash": base64.StdEncoding.EncodeToString(root), "file_hash": base64.StdEncoding.EncodeToString(file)}
	}
	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		var call struct {
			ID     uint64          `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		raw, _ := io.ReadAll(request.Body)
		if err := json.Unmarshal(raw, &call); err != nil {
			http.Error(response, "bad request", http.StatusBadRequest)
			return
		}
		head := chain.head.Load()
		now := time.Now().Unix()
		var result any
		switch call.Method {
		case "getConsensusBlock":
			chain.consensus.Add(1)
			if chain.staleForever || chain.stale.Add(-1) >= 0 {
				head = chain.staleHead
			}
			result = map[string]any{"@type": "ext.blocks.consensusBlock", "consensus_block": head, "timestamp": now,
				"last_block_utime": now}
		case "getMasterchainInfo":
			result = map[string]any{"@type": "blocks.masterchainInfo", "last": block(head),
				"init": map[string]any{"root_hash": initRoot, "file_hash": initFile}}
		case "getAddressInformation":
			var params struct {
				Seqno uint64 `json:"seqno"`
			}
			_ = json.Unmarshal(call.Params, &params)
			result = map[string]any{"@type": "raw.fullAccountState", "block_id": block(params.Seqno), "state": "uninitialized"}
		default:
			http.Error(response, "unknown method", http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "result": result})
	})
	for range 3 {
		server := httptest.NewServer(handler)
		t.Cleanup(server.Close)
		chain.urls = append(chain.urls, server.URL)
	}
	return chain
}

// fenceBlock is the fake chain's block identity at seqno.
func fenceBlock(seqno uint64) ([]byte, []byte) {
	suffix := string(rune('a' + seqno%26))
	return []byte(strings.Repeat("r", 31) + suffix), []byte(strings.Repeat("f", 31) + suffix)
}

// fenceReader is one process's reader over a state directory's fences, as
// a node opens it: the registry fence and the Service Actor fence.
func fenceReader(t *testing.T, chain *fenceChain, locator *nativecore.Locator, directory string) (*ServiceActorReader, *SimplifiedNativeResolver) {
	t.Helper()
	adapter, err := New(Config{Network: locator.Network.NetworkId, Endpoints: chain.urls, Quorum: 2})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewSimplifiedNativeResolver(adapter, locator, filepath.Join(directory, "registry.checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := NewServiceActorReader(ServiceActorReaderConfig{Chain: adapter, Network: locator.Network,
		ActorCodeHash: "tvm-cell-sha256:" + strings.Repeat("ab", 32), Registry: registry,
		CheckpointPath: filepath.Join(directory, "service-actor.checkpoint")})
	if err != nil {
		t.Fatal(err)
	}
	return reader, registry
}

func fenceDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func fenceValue(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(raw))
}

func isBadSequence(err error) bool {
	var protocol *nativecore.ProtocolError
	return errors.As(err, &protocol) && protocol.Code == nativecore.ErrBadSequence
}

// A one-shot command (a buyer's `buy`) and a long-running process (its
// `serve`) share one state directory. The command opens a session, another
// process advances the shared fence past the session's checkpoint, and the
// command then reads again inside its session at the checkpoint it pinned.
// That read is not a regression: the session's checkpoint was checked
// against the fence when it was opened.
func TestASessionReadsAtItsPinAfterAnotherProcessAdvancedTheFence(t *testing.T) {
	locator := registryLocator(t)
	chain := newFenceChain(t, locator, 100)
	directory := fenceDirectory(t)
	buyReader, _ := fenceReader(t, chain, locator, directory)
	serveReader, _ := fenceReader(t, chain, locator, directory)
	ctx := context.Background()

	session, err := buyReader.Begin(ctx)
	if err != nil || session.Checkpoint() != 100 {
		t.Fatalf("open the command's session: %v", err)
	}
	if _, found, err := session.ResolveRegistry(ctx, registryOtherCap); err != nil || found {
		t.Fatalf("first read in the session: found %v, %v", found, err)
	}
	// The registry fence records the session's checkpoint once a read at it
	// validated.
	if got := fenceValue(t, filepath.Join(directory, "registry.checkpoint")); got != "100" {
		t.Fatalf("the registry fence after the session's first read is %s, want 100", got)
	}

	chain.head.Store(105)
	served, err := serveReader.Begin(ctx)
	if err != nil {
		t.Fatalf("open the other process's session: %v", err)
	}
	if _, _, err := served.ResolveRegistry(ctx, registryOtherCap); err != nil {
		t.Fatalf("the other process's read: %v", err)
	}
	if got := fenceValue(t, filepath.Join(directory, "registry.checkpoint")); got != "105" {
		t.Fatalf("the shared registry fence is %s, want 105", got)
	}

	if _, found, err := session.ResolveRegistry(ctx, registryOtherCap); err != nil || found {
		t.Fatalf("a read at the session's own pin after another process advanced the fence: found %v, %v", found, err)
	}
	if got := fenceValue(t, filepath.Join(directory, "registry.checkpoint")); got != "105" {
		t.Fatalf("the read inside the older session moved the fence to %s", got)
	}
}

// The same holds inside one process: a session stays readable at its pin
// after a later session of the same reader advanced the fence.
func TestASessionReadsAtItsPinAfterALaterSessionOfTheSameReader(t *testing.T) {
	locator := registryLocator(t)
	chain := newFenceChain(t, locator, 200)
	reader, _ := fenceReader(t, chain, locator, fenceDirectory(t))
	ctx := context.Background()
	older, err := reader.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	chain.head.Store(201)
	newer, err := reader.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := newer.ResolveRegistry(ctx, registryOtherCap); err != nil {
		t.Fatalf("the newer session's read: %v", err)
	}
	if _, _, err := older.ResolveRegistry(ctx, registryOtherCap); err != nil {
		t.Fatalf("the older session's read at its pin: %v", err)
	}
}

// Rollback protection is unchanged: a session is never opened below what
// either fence of the state directory has recorded, whichever process or
// read recorded it.
func TestASessionIsNeverOpenedBelowEitherFence(t *testing.T) {
	locator := registryLocator(t)
	ctx := context.Background()

	t.Run("the Service Actor fence alone", func(t *testing.T) {
		// Only the Service Actor fence holds 300, as another process
		// recorded it; the registry fence is empty.
		chain := newFenceChain(t, locator, 299)
		directory := fenceDirectory(t)
		if err := os.WriteFile(filepath.Join(directory, "service-actor.checkpoint"), []byte("300\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		reader, _ := fenceReader(t, chain, locator, directory)
		if _, err := reader.Begin(ctx); !isBadSequence(err) {
			t.Fatalf("a session below the Service Actor fence was opened: %v", err)
		}
	})

	t.Run("a session of another process", func(t *testing.T) {
		chain := newFenceChain(t, locator, 350)
		directory := fenceDirectory(t)
		first, _ := fenceReader(t, chain, locator, directory)
		if _, err := first.Begin(ctx); err != nil {
			t.Fatal(err)
		}
		chain.head.Store(349)
		second, _ := fenceReader(t, chain, locator, directory)
		if _, err := second.Begin(ctx); !isBadSequence(err) {
			t.Fatalf("a session below another process's session was opened: %v", err)
		}
	})

	t.Run("the registry fence advanced by a fresh read", func(t *testing.T) {
		chain := newFenceChain(t, locator, 400)
		directory := fenceDirectory(t)
		reader, _ := fenceReader(t, chain, locator, directory)
		if _, err := reader.Begin(ctx); err != nil {
			t.Fatal(err)
		}
		chain.head.Store(410)
		_, other := fenceReader(t, chain, locator, directory)
		if _, found, err := other.ResolveState(ctx, registryOtherCap, ""); err != nil || found {
			t.Fatalf("a fresh registry read at the head: found %v, %v", found, err)
		}
		if got := fenceValue(t, filepath.Join(directory, "registry.checkpoint")); got != "410" {
			t.Fatalf("the registry fence is %s, want 410", got)
		}
		// The Service Actor fence is still at 400; the registry fence at
		// 410 alone must refuse a session at 405.
		chain.head.Store(405)
		late, _ := fenceReader(t, chain, locator, directory)
		if _, err := late.Begin(ctx); !isBadSequence(err) {
			t.Fatalf("a session below the registry fence was opened: %v", err)
		}
		if got := fenceValue(t, filepath.Join(directory, "service-actor.checkpoint")); got != "400" {
			t.Fatalf("a refused session moved the Service Actor fence to %s", got)
		}
	})

	t.Run("an exact checkpoint below the durable fence through the public resolver", func(t *testing.T) {
		chain := newFenceChain(t, locator, 600)
		directory := fenceDirectory(t)
		reader, _ := fenceReader(t, chain, locator, directory)
		session, err := reader.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := session.ResolveRegistry(ctx, registryOtherCap); err != nil {
			t.Fatal(err)
		}
		account, err := locator.Locate(registryOtherCap)
		if err != nil {
			t.Fatal(err)
		}
		root, file := fenceBlock(599)
		_, other := fenceReader(t, chain, locator, directory)
		_, _, err = other.ResolveNativeAtCheckpoint(ctx, account.Address,
			&nativev1.DNSCheckpointV1{Workchain: -1, Sequence: 599, RootHash: root, FileHash: file})
		if !isBadSequence(err) {
			t.Fatalf("an exact checkpoint below the durable fence was served: %v", err)
		}
	})

	t.Run("an older checkpoint through the public resolver", func(t *testing.T) {
		chain := newFenceChain(t, locator, 500)
		directory := fenceDirectory(t)
		_, registry := fenceReader(t, chain, locator, directory)
		if _, _, err := registry.ResolveState(ctx, registryOtherCap, ""); err != nil {
			t.Fatal(err)
		}
		chain.head.Store(499)
		if _, _, err := registry.ResolveState(ctx, registryOtherCap, ""); !isBadSequence(err) {
			t.Fatalf("a fresh read below the fence was served: %v", err)
		}
	})
}

// An observation that another process overtook while it was being made is
// replaced by a fresh one; an endpoint set that keeps serving a checkpoint
// below the record is refused after beginAttempts observations.
func TestBeginRetriesAnOvertakenObservationAndRefusesAPersistentlyOldChain(t *testing.T) {
	locator := registryLocator(t)
	ctx := context.Background()

	t.Run("overtaken once", func(t *testing.T) {
		chain := newFenceChain(t, locator, 700)
		directory := fenceDirectory(t)
		first, _ := fenceReader(t, chain, locator, directory)
		if _, err := first.Begin(ctx); err != nil {
			t.Fatal(err)
		}
		chain.head.Store(705)
		chain.staleHead = 690
		chain.stale.Store(3) // one quorum read of the three endpoints
		second, _ := fenceReader(t, chain, locator, directory)
		session, err := second.Begin(ctx)
		if err != nil || session.Checkpoint() != 705 {
			t.Fatalf("an overtaken observation was not replaced by a fresh one: %v", err)
		}
	})

	t.Run("a refusal that is not behind the record", func(t *testing.T) {
		chain := newFenceChain(t, locator, 900)
		directory := fenceDirectory(t)
		if err := os.WriteFile(filepath.Join(directory, "service-actor.checkpoint"), []byte("corrupt\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		reader, _ := fenceReader(t, chain, locator, directory)
		if _, err := reader.Begin(ctx); err == nil {
			t.Fatal("a session was opened over a corrupt fence")
		}
		// One quorum read of the three endpoints: only an observation behind
		// the record is made again.
		if calls := chain.consensus.Load(); calls != 3 {
			t.Fatalf("consensus was asked %d times, want 3", calls)
		}
	})

	t.Run("persistently old", func(t *testing.T) {
		chain := newFenceChain(t, locator, 800)
		directory := fenceDirectory(t)
		first, _ := fenceReader(t, chain, locator, directory)
		if _, err := first.Begin(ctx); err != nil {
			t.Fatal(err)
		}
		chain.staleHead, chain.staleForever = 790, true
		chain.consensus.Store(0)
		second, _ := fenceReader(t, chain, locator, directory)
		if _, err := second.Begin(ctx); !isBadSequence(err) {
			t.Fatalf("a chain below the record was served: %v", err)
		}
		if calls := chain.consensus.Load(); calls != 3*beginAttempts {
			t.Fatalf("consensus was asked %d times, want %d", calls, 3*beginAttempts)
		}
		if got := fenceValue(t, filepath.Join(directory, "service-actor.checkpoint")); got != "800" {
			t.Fatalf("the refused observations moved the fence to %s", got)
		}
	})
}
