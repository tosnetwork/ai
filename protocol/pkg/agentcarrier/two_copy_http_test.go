package agentcarrier

import (
	"context"
	"crypto/sha256"
	"errors"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacket"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
)

type restartRelay struct {
	deposits        atomic.Int64
	f               *fixture
	root, addr, url string
	server          *httptest.Server
	store           *agentpacketrelay.V2Store
	client          *agentpacketrelay.V2Client
}

func (r *restartRelay) start(t *testing.T) {
	t.Helper()
	store, e := agentpacketrelay.OpenV2Store(r.root, agentpacketrelay.DefaultV2Limits(1024, 64<<20), r.f.clock.Now(), agentpacketrelay.V2OpenOptions{})
	if e != nil {
		t.Fatal(e)
	}
	var handler *agentpacketrelay.V2Server
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "PUT" && strings.Contains(req.URL.Path, "/envelopes/") {
			r.deposits.Add(1)
		}
		handler.ServeHTTP(w, req)
	}))
	if r.addr != "" {
		if e = server.Listener.Close(); e != nil {
			t.Fatal(e)
		}
		server.Listener, e = net.Listen("tcp", r.addr)
		if e != nil {
			t.Fatal(e)
		}
	}
	r.addr = server.Listener.Addr().String()
	r.url = "https://" + r.addr
	handler, e = agentpacketrelay.NewV2Server(agentpacketrelay.V2ServerConfig{Store: store, URL: r.url, Verifier: r.f.verifier, Now: r.f.clock.Now, Directory: true})
	if e != nil {
		t.Fatal(e)
	}
	server.StartTLS()
	r.server = server
	r.store = store
	if r.client == nil {
		r.client, e = agentpacketrelay.NewV2Client(r.url, server.Client().Transport, r.f.clock.Now)
		if e != nil {
			t.Fatal(e)
		}
	}
}
func (r *restartRelay) stop(t *testing.T) {
	t.Helper()
	if r.server != nil {
		r.server.Close()
		r.server = nil
	}
	if r.store != nil {
		if e := r.store.Close(); e != nil {
			t.Fatal(e)
		}
		r.store = nil
	}
}
func TestTwoRealV2RelaysRecoverTheirSecondCopyAndAdmitOnce(t *testing.T) {
	f := newFixture(t)
	one := &restartRelay{f: f, root: filepath.Join(f.config.StateDir, "service-one")}
	two := &restartRelay{f: f, root: filepath.Join(f.config.StateDir, "service-two")}
	one.start(t)
	two.start(t)
	defer one.stop(t)
	defer two.stop(t)
	clients := map[string]*agentpacketrelay.V2Client{one.url: one.client, two.url: two.client}
	f.lane.config.Relay = func(url string) (Relay, error) {
		c, ok := clients[url]
		if !ok {
			return nil, ErrUnavailable
		}
		return c, nil
	}
	bc := f.config
	bc.StateDir = t.TempDir()
	if e := os.Chmod(bc.StateDir, 0700); e != nil {
		t.Fatal(e)
	}
	bc.AgentID = f.bob.agent
	bc.Delegation = f.bob.wire
	bc.Relays = []string{one.url, two.url}
	bc.Relay = f.lane.config.Relay
	bc.SignCard = func(_ context.Context, c agentpacketseal.KeyCard) ([]byte, error) { return f.cardPacket(f.bob, c), nil }
	var mu sync.Mutex
	admitted := map[[32]byte]bool{}
	executions := 0
	bc.Store = func(_ context.Context, raw []byte) error {
		mu.Lock()
		defer mu.Unlock()
		h := sha256.Sum256(raw)
		if !admitted[h] {
			admitted[h] = true
			executions++
		}
		return nil
	}
	manager, e := OpenCredentialManager(t.Context(), bc, f.bob.transport, func(context.Context, string) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := manager.Close(); e != nil {
			t.Error(e)
		}
	}()
	bc.Credentials = manager
	bob, e := Open(t.Context(), bc)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := bob.Close(); e != nil {
			t.Error(e)
		}
	}()
	publisher, e := OpenPublisher(bob, manager, PublicationConfig{Directories: bc.Relays, Directory: func(url string) (Directory, error) { return clients[url], nil }, PublishRailCard: true})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := publisher.Close(); e != nil {
			t.Error(e)
		}
	}()
	if view, e := publisher.Publish(t.Context()); e != nil || view.HintTargets != 2 || view.PolicyTargets != 2 {
		t.Fatal("real V2 publication failed", view, e)
	}
	routes, e := OpenResolver(f.lane, ResolverConfig{Directories: bc.Relays, Directory: func(url string) (Directory, error) {
		c, ok := clients[url]
		if !ok {
			return nil, ErrUnavailable
		}
		return c, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := routes.Close(); e != nil {
			t.Error(e)
		}
	}()
	scheduler, e := OpenScheduler(f.lane, routes)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := scheduler.Close(); e != nil {
			t.Error(e)
		}
	}()
	two.stop(t)
	f.clock.n.Store(int64(start + 1))
	if _, e = f.lane.Queue(t.Context(), "real-two", f.message(f.alice, f.bob), start+7200); e != nil {
		t.Fatal(e)
	}
	view, e := scheduler.Advance(t.Context(), "real-two", Route{})
	if e != nil || view.Copies != 1 {
		t.Fatal("surviving relay did not carry", view, e)
	}
	saved, e := scheduler.snapshot(t.Context(), "real-two")
	if e != nil {
		t.Fatal(e)
	}
	id := agentpacketseal.AckHash(saved.Generations[0].Secret)
	// Restart uses the same listener address and actual on-disk V2 store. The
	// clock passes the persisted replay floor's F+1 restart delay.
	f.clock.n.Store(int64(start + 141))
	two.start(t)
	if e = one.store.Replay().Record(uint64(f.clock.Now().Unix())); e != nil {
		t.Fatal(e)
	}
	view, e = scheduler.Advance(t.Context(), "real-two", Route{})
	if e != nil || view.Copies != 2 {
		t.Fatal("returning relay did not get its second copy", view, e)
	}
	received, e := bob.Poll(t.Context())
	if e != nil || received.Acknowledged != 2 || executions != 1 {
		t.Fatal("two copies were not deduplicated and acknowledged", received, executions, e)
	}
	for _, client := range []*agentpacketrelay.V2Client{one.client, two.client} {
		credential, e := manager.Owner(t.Context(), clientURL(client, one, two))
		if e != nil {
			t.Fatal(e)
		}
		entries, e := client.List(t.Context(), f.bob.agent, credential.wire, credential.holder)
		if e != nil {
			t.Fatal(e)
		}
		for _, entry := range entries {
			if entry.EnvelopeID == id {
				t.Fatal("acknowledged copy remains visible")
			}
		}
	}
	// A separately acknowledged delivery must not get its second copy when the
	// failed relay returns. Count HTTP PUTs, not just the visible mailbox.
	two.stop(t)
	f.clock.n.Store(int64(start + 150))
	p, e := packet(f.message(f.alice, f.bob))
	if e != nil {
		t.Fatal(e)
	}
	p.Sequence = 2
	p.Nonce[0] = 2
	next, e := agentpacket.EncodeJSON(p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.lane.Queue(t.Context(), "real-ack", next, start+7200); e != nil {
		t.Fatal(e)
	}
	view, e = scheduler.Advance(t.Context(), "real-ack", Route{})
	if e != nil || view.Copies != 1 {
		t.Fatal(view, e)
	}
	received, e = bob.Poll(t.Context())
	if e != nil && !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	if received.Stored != 1 || received.Acknowledged != 1 || executions != 2 {
		t.Fatal("surviving copy did not reach the inbox", received, executions)
	}
	// The business lane authenticated its receipt; transport does not invent it.
	if e = f.lane.Complete(t.Context(), "real-ack"); e != nil {
		t.Fatal(e)
	}
	before := two.deposits.Load()
	f.clock.n.Store(int64(start + 300))
	two.start(t)
	if e = one.store.Replay().Record(uint64(f.clock.Now().Unix())); e != nil {
		t.Fatal(e)
	}
	view, e = scheduler.Advance(t.Context(), "real-ack", Route{})
	if e != nil || view.State != "complete" || two.deposits.Load() != before {
		t.Fatal("acknowledged delivery was deposited again", view, e)
	}

}
func clientURL(c *agentpacketrelay.V2Client, one, two *restartRelay) string {
	if c == one.client {
		return one.url
	}
	return two.url
}
