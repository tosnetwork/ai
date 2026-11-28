package agentcarrier

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (fn transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }
func TestLaneUsesRealV2HTTPAndJournalsBeforeTheRequest(t *testing.T) {
	f := newFixture(t)
	store, err := agentpacketrelay.OpenV2Store(filepath.Join(f.config.StateDir, "relay-store"), agentpacketrelay.DefaultV2Limits(1024, 64<<20), f.clock.Now(), agentpacketrelay.V2OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err = store.Close(); err != nil {
			t.Error(err)
		}
	}()
	var active atomic.Pointer[agentpacketrelay.V2Server]
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := active.Load()
		if h == nil {
			w.WriteHeader(503)
			return
		}
		h.ServeHTTP(w, r)
	}))
	defer server.Close()
	handler, err := agentpacketrelay.NewV2Server(agentpacketrelay.V2ServerConfig{Store: store, URL: server.URL, Verifier: f.verifier, Now: f.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	active.Store(handler)
	base := server.Client().Transport
	client, err := agentpacketrelay.NewV2Client(server.URL, transportFunc(func(r *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(r.URL.Path, "/v2/") {
			t.Error("retired route requested")
		}
		if r.Method == "PUT" && strings.Contains(r.URL.Path, "/envelopes/") {
			body, err := r.GetBody()
			if err != nil {
				return nil, err
			}
			raw, readErr := io.ReadAll(body)
			closeErr := body.Close()
			if readErr != nil {
				return nil, readErr
			}
			if closeErr != nil {
				return nil, closeErr
			}
			saved, err := f.lane.readDelivery(deliveryName("tls-id"))
			if err != nil || len(saved.Generations) != 1 || !bytes.Equal(saved.Generations[0].Envelope, raw) {
				t.Error("production request preceded its durable envelope")
			}
		}
		return base.RoundTrip(r)
	}), f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	factory := f.lane.config.Relay
	f.lane.config.Relay = func(url string) (Relay, error) {
		if url == server.URL {
			return client, nil
		}
		return factory(url)
	}
	route := f.peerRoute()
	record, err := agenttransport.DecodeHintRecord(route.HintRecord)
	if err != nil {
		t.Fatal(err)
	}
	record.Hint.Relays = []string{server.URL}
	record.Hint, err = agenttransport.SignHint(record.Hint, f.bob.transport)
	if err != nil {
		t.Fatal(err)
	}
	route.HintRecord, err = record.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.lane.Queue(t.Context(), "tls-id", f.message(f.alice, f.bob), start+7200); err != nil {
		t.Fatal(err)
	}
	result, err := f.lane.Attempt(t.Context(), "tls-id", route, 0)
	if err != nil || !result.Accepted {
		t.Fatal("V2 deposit failed", result, err)
	}
	// Exercise credentialed list/fetch and secret ACK through the same real client.
	plain, err := agentpacketrelay.NewV2Client(server.URL, base, f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	raw := inbound(t, f, f.message(f.bob, f.alice))
	if err = plain.Deposit(t.Context(), raw, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err = f.lane.TrackRelays(t.Context(), []string{server.URL}, start+3600); err != nil {
		t.Fatal(err)
	}
	view, err := f.lane.Poll(t.Context())
	if err != nil || view.Stored != 1 || view.Acknowledged != 1 {
		t.Fatal("V2 receive failed", view, err)
	}
}
