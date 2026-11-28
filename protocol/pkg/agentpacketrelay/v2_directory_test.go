package agentpacketrelay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketseal"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

func signedDirectoryHint(t testing.TB, f *v2HTTPFixture, tag byte, issued, expires uint64, relays []string) ([]byte, [32]byte) {
	t.Helper()
	c, err := agenttransport.DecodeCredential(f.wire)
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.Delegation()
	if err != nil {
		t.Fatal(err)
	}
	key := v2TestKey("http-transport")
	if tag != 0 {
		key = v2TestKey(fmt.Sprint("directory-transport-", tag))
		copy(d.TransportKey[:], key.Public().(ed25519.PublicKey))
	}
	raw, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	value := "sha256:" + hex.EncodeToString(digest[:])
	found := false
	for _, entry := range f.source.state.GetAgent().DelegationAdmissions {
		if entry.Digest == value {
			found = true
		}
	}
	if !found {
		f.source.state.GetAgent().DelegationAdmissions = append(f.source.state.GetAgent().DelegationAdmissions, &nativev1.DelegationAdmissionV1{Digest: value, AdmissionEpoch: d.AuthorizationEpoch})
	}
	h, err := agenttransport.SignHint(agenttransport.Hint{Delegation: d, IssuedAt: issued, ExpiresAt: expires, Relays: relays}, key)
	if err != nil {
		t.Fatal(err)
	}
	record, err := (agenttransport.HintRecord{Hint: h}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	return record, digest
}
func directoryHint(t testing.TB, f *v2HTTPFixture, tag byte) ([]byte, [32]byte) {
	now := unixNow(f.clock.Now())
	return signedDirectoryHint(t, f, tag, now, now+21600, []string{f.s.relay})
}
func fWaitRequest(t testing.TB, f *v2HTTPFixture, ctx context.Context, seconds string) (*http.Request, *httptest.ResponseRecorder) {
	t.Helper()
	r := f.request(t, "GET", f.mail(), nil, true).WithContext(ctx)
	r.Header.Set("TOS-Relay-Wait", seconds)
	return r, httptest.NewRecorder()
}

func TestV2DirectoryCodecBounds(t *testing.T) {
	entries := make([]HintIndexEntry, 4)
	for i := range entries {
		entries[i] = HintIndexEntry{[32]byte{byte(i)}, 1800000000, agenttransport.MaxHintRecordSize}
	}
	raw, err := EncodeHintIndex(entries)
	if err != nil || len(raw) != 209 {
		t.Fatal(len(raw), err)
	}
	decoded, err := DecodeHintIndex(raw)
	if err != nil || len(decoded) != 4 {
		t.Fatal(err)
	}
	badOrder := append([]HintIndexEntry(nil), entries...)
	badOrder[1] = badOrder[0]
	if _, err = EncodeHintIndex(badOrder); err == nil {
		t.Fatal("duplicate digest accepted")
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), 0), raw[:len(raw)-1], bytes.Repeat([]byte{0}, len(raw))} {
		if _, err = DecodeHintIndex(bad); err == nil {
			t.Fatal("malformed hint index accepted")
		}
	}
	if _, err = EncodeRevocations(nil); err == nil {
		t.Fatal("zero revocations accepted")
	}
	if _, err = EncodeRevocations(make([]Revocation, 33)); err == nil {
		t.Fatal("33 revocations accepted")
	}
	revs := make([]Revocation, 32)
	for i := range revs {
		revs[i] = Revocation{[32]byte{byte(i)}, 1800000000 + MaxRevocationLifetime}
	}
	raw, err = EncodeRevocations(revs)
	if err != nil || len(raw) != MaxRevocationRequestBytes {
		t.Fatal(err)
	}
	got, err := DecodeRevocations(raw)
	if err != nil || len(got) != 32 {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{append(bytes.Clone(raw), 0), raw[:len(raw)-1], bytes.Repeat([]byte{0}, len(raw))} {
		if _, err = DecodeRevocations(bad); err == nil {
			t.Fatal("malformed revocation request accepted")
		}
	}
	if validRevocationTime(^uint64(0), 1800000000) || validRevocationTime(1800000000+MaxRevocationLifetime+1, 1800000000) {
		t.Fatal("revocation deadline overflow")
	}
}
func TestV2RevocationStopsDescendantsButKeepsStoredEnvelopes(t *testing.T) {
	f := newV2HTTP(t)
	now := unixNow(f.clock.Now())
	e := f.r.seal(t, testPacket(1), now+3600)
	path := f.mail() + "/" + hex.EncodeToString(e.id[:])
	f.serve(t, "PUT", path, e.envelope, true, 201)
	c, err := agenttransport.DecodeCredential(f.wire)
	if err != nil {
		t.Fatal(err)
	}
	values, err := c.ChainValues()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := agenttransport.IssueCredential(mustDelegation(t, c), v2TestKey("http-transport"), f.holder.Public().(ed25519.PublicKey), []agenttransport.Caveat{agenttransport.NotBeforeCaveat(now - 1), agenttransport.NotAfterCaveat(now + 3600), agenttransport.OperationsCaveat(agenttransport.OperationRevoke), agenttransport.RelayCaveat(f.s.relay)})
	if err != nil {
		t.Fatal(err)
	}
	contact := f.wire
	f.wire = owner
	body, err := EncodeRevocations([]Revocation{{values[1], now + 3600}})
	if err != nil {
		t.Fatal(err)
	}
	f.serve(t, "POST", "/v2/mailboxes/"+f.r.agentID+"/revocations", body, true, 204)
	f.wire = contact
	f.serve(t, "GET", f.mail(), nil, true, 403)
	child := v2TestKey("revoked-child")
	appended, err := agenttransport.AppendCredentialBlock(contact, f.holder, child.Public().(ed25519.PublicKey), []agenttransport.Caveat{agenttransport.NotAfterCaveat(now + 1800)})
	if err != nil {
		t.Fatal(err)
	}
	f.wire = appended
	f.holder = child
	e2 := f.r.seal(t, testPacket(2), now+3600)
	f.serve(t, "PUT", f.mail()+"/"+hex.EncodeToString(e2.id[:]), e2.envelope, true, 403)
	if f.s.store.Usage().ContactEntries != 1 {
		t.Fatal("revocation deleted stored envelope")
	}
	f.serve(t, "POST", path+"/ack", e.secret[:], false, 204)
	v2Close(t, f.s.store)
	f.clock.at = f.clock.at.Add(141 * time.Second)
	f.s.store = v2Open(t, f.path, DefaultV2Limits(1024, 64<<20), f.clock.Now())
	f.serve(t, "PUT", f.mail()+"/"+hex.EncodeToString(e2.id[:]), e2.envelope, true, 403)
}
func mustDelegation(t testing.TB, c *agenttransport.Credential) []byte {
	t.Helper()
	d, err := c.DelegationBytes()
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func TestV2RevocationQuotaAndDeadline(t *testing.T) {
	f := newV2HTTP(t)
	now := unixNow(f.clock.Now())
	path := "/v2/mailboxes/" + f.r.agentID + "/revocations"
	body, err := EncodeRevocations([]Revocation{{[32]byte{1}, now + MaxRevocationLifetime + 1}})
	if err != nil {
		t.Fatal(err)
	}
	f.serve(t, "POST", path, body, true, 400)
	// The fixture's proof ledger is finite too; record batches without the HTTP
	// proof limit here, then prove that the real endpoint returns the quota code.
	checked := v2Checked(t, f.wire, f.holder, f.r.agentID, now, 120)
	for batch := range 32 {
		entries := make([]Revocation, 32)
		for i := range entries {
			entries[i] = Revocation{sha256.Sum256([]byte(fmt.Sprint(batch, "/", i))), now + 3600}
		}
		if err = f.s.store.revoke(t.Context(), f.r.agentID, entries, checked, now); err != nil {
			t.Fatal(err)
		}
	}
	body, err = EncodeRevocations([]Revocation{{[32]byte{99}, now + 3600}})
	if err != nil {
		t.Fatal(err)
	}
	f.serve(t, "POST", path, body, true, 507)
	if f.s.store.revocationCount != 1024 {
		t.Fatal(f.s.store.revocationCount)
	}
	f.clock.at = f.clock.at.Add(3600 * time.Second)
	if err = f.s.store.Sweep(f.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if f.s.store.revocationCount != 0 || len(f.s.store.revocations) != 0 {
		t.Fatal("revocations not reclaimed")
	}
}
func TestV2DirectorySlotsConflictAndPersistence(t *testing.T) {
	f := newV2HTTP(t)
	path := "/v2/hints/" + f.r.agentID
	var first []byte
	var firstID [32]byte
	for i := range 4 {
		raw, digest := directoryHint(t, f, byte(i))
		f.serve(t, "PUT", path, raw, false, 204)
		if i == 0 {
			first, firstID = raw, digest
		}
	}
	raw, _ := directoryHint(t, f, 4)
	f.serve(t, "PUT", path, raw, false, 507)
	w := f.serve(t, "GET", path, nil, false, 200)
	entries, err := DecodeHintIndex(w.Body.Bytes())
	if err != nil || len(entries) != 4 {
		t.Fatal(entries, err)
	}
	f.serve(t, "PUT", path, first, false, 204)
	conflict, _ := signedDirectoryHint(t, f, 0, unixNow(f.clock.Now()), unixNow(f.clock.Now())+21599, []string{f.s.relay})
	f.serve(t, "PUT", path, conflict, false, 409)
	v2Close(t, f.s.store)
	f.s.store = v2Open(t, f.path, DefaultV2Limits(1024, 64<<20), f.clock.Now())
	w = f.serve(t, "GET", path+"/"+hex.EncodeToString(firstID[:]), nil, false, 200)
	if !bytes.Equal(w.Body.Bytes(), first) {
		t.Fatal("hint changed on restart")
	}
	f.clock.at = f.clock.at.Add(21600 * time.Second)
	if err = f.s.store.Sweep(f.clock.Now()); err != nil {
		t.Fatal(err)
	}
	f.serve(t, "GET", path, nil, false, 404)
}
func TestV2DirectoryDoesNotEvictLiveAgent(t *testing.T) {
	f := newV2HTTP(t)
	f.s.directory = true
	f.s.store.controlLimits.DirectoryAgents = 1
	raw, _ := directoryHint(t, f, 0)
	f.serve(t, "PUT", "/v2/hints/"+f.r.agentID, raw, false, 204)
	other := newV2HTTP(t)
	raw, _ = directoryHint(t, other, 0)
	f.source.state = other.source.state
	f.serve(t, "PUT", "/v2/hints/"+other.r.agentID, raw, false, 507)
	if len(f.s.store.hints) != 1 || len(f.s.store.hints[f.r.agentID]) != 1 {
		t.Fatal("live directory displaced")
	}
}
func TestV2HintMustNameRelayUnlessDirectory(t *testing.T) {
	f := newV2HTTP(t)
	raw, _ := signedDirectoryHint(t, f, 0, unixNow(f.clock.Now()), unixNow(f.clock.Now())+21600, []string{"https://127.0.0.2"})
	path := "/v2/hints/" + f.r.agentID
	f.serve(t, "PUT", path, raw, false, 403)
	f.s.directory = true
	f.serve(t, "PUT", path, raw, false, 204)
}

func TestV2ChainRevocationInvalidatesMailboxesAndHintsAtBothRelays(t *testing.T) {
	first := newV2HTTP(t)
	second := newV2HTTP(t)
	second.r = first.r
	second.clock = first.clock
	second.source = first.source
	second.config = first.config
	second.holder = first.holder
	second.s.now = first.clock.Now
	second.s.relay = "https://127.0.0.2"
	verifier, err := NewV2FinalizedVerifier(second.config, second.source)
	if err != nil {
		t.Fatal(err)
	}
	second.s.verifier = verifier
	c, err := agenttransport.DecodeCredential(first.wire)
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := c.Blocks()
	if err != nil {
		t.Fatal(err)
	}
	caveats := blocks[0].Caveats
	for i := range caveats {
		if caveats[i].Type == agenttransport.CaveatRelay {
			caveats[i] = agenttransport.RelayCaveat(second.s.relay)
		}
	}
	second.wire, err = agenttransport.IssueCredential(mustDelegation(t, c), v2TestKey("http-transport"), second.holder.Public().(ed25519.PublicKey), caveats)
	if err != nil {
		t.Fatal(err)
	}
	now := unixNow(first.clock.Now())
	raw, digest := signedDirectoryHint(t, first, 0, now, now+21600, []string{first.s.relay, second.s.relay})
	path := "/v2/hints/" + first.r.agentID
	for _, f := range []*v2HTTPFixture{first, second} {
		f.serve(t, "GET", f.mail(), nil, true, 200)
		f.serve(t, "PUT", path, raw, false, 204)
		f.serve(t, "GET", path+"/"+hex.EncodeToString(digest[:]), nil, false, 200)
	}
	first.source.state.GetAgent().DelegationAdmissions = nil
	first.clock.at = first.clock.at.Add(300 * time.Second)
	for _, f := range []*v2HTTPFixture{first, second} {
		if err = f.s.store.Replay().Record(unixNow(f.clock.Now())); err != nil {
			t.Fatal(err)
		}
		f.serve(t, "GET", f.mail(), nil, true, 403)
		f.serve(t, "GET", path, nil, false, 404)
		if len(f.s.store.hints) != 0 {
			t.Fatal("revoked hint was retained as live")
		}
	}
}
func TestV2DirectoryRefusesPoisonedTimeAndSignature(t *testing.T) {
	f := newV2HTTP(t)
	now := unixNow(f.clock.Now())
	path := "/v2/hints/" + f.r.agentID
	for _, issued := range []uint64{now + 301, ^uint64(0) - 1} {
		expires := issued + 1
		raw, _ := signedDirectoryHint(t, f, 0, issued, expires, []string{f.s.relay})
		f.serve(t, "PUT", path, raw, false, 400)
	}
	raw, _ := directoryHint(t, f, 0)
	raw = bytes.Clone(raw)
	record, err := agenttransport.DecodeHintRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	record.Hint.Signature[0] ^= 1
	raw, err = record.Encode()
	if err != nil {
		t.Fatal(err)
	}
	f.serve(t, "PUT", path, raw, false, 400)
	if len(f.s.store.hints) != 0 {
		t.Fatal("unverified hint stored")
	}
}
func TestV2DirectorySnapshotDoesNotEmitExpiredCachedPass(t *testing.T) {
	f := newV2HTTP(t)
	path := "/v2/hints/" + f.r.agentID
	for i := range 2 {
		raw, _ := directoryHint(t, f, byte(i))
		f.serve(t, "PUT", path, raw, false, 204)
	}
	f.source.err = agenttransport.ErrUnavailable
	f.clock.at = f.clock.at.Add(590 * time.Second)
	f.source.after = func() { f.clock.at = f.clock.at.Add(6 * time.Second) }
	f.serve(t, "GET", path, nil, false, 503)
}
func TestV2RevocationCommitRechecksLocalAuthority(t *testing.T) {
	f := newV2HTTP(t)
	now := unixNow(f.clock.Now())
	request := f.request(t, "GET", f.mail(), nil, true)
	c, err := agenttransport.CheckRequest(agenttransport.Request{AgentID: f.r.agentID, Operation: agenttransport.OperationList, Proof: agenttransport.ProofRequest{RelayURL: f.s.relay, Method: "GET", Path: f.mail()}, CredentialValue: request.Header.Get("TOS-Relay-Credential"), ProofValue: request.Header.Get("TOS-Relay-Proof"), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	chains, err := c.Credential.ChainValues()
	if err != nil {
		t.Fatal(err)
	}
	// This models a request admitted before a concurrent revocation commits.
	f.s.store.mu.Lock()
	err = f.s.store.writeRevocationsLocked(f.r.agentID, map[[32]byte]uint64{chains[1]: now + 3600})
	f.s.store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	e := f.r.seal(t, testPacket(1), now+3600)
	header, err := agentpacketseal.ParseEnvelope(e.envelope)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.s.store.deposit(t.Context(), depositInput{header, e.envelope, v2Loopback(1), now, now + 3600}, &c, v2Usage{32, 2 << 20})
	if !errors.Is(err, ErrCredentialRevoked) {
		t.Fatal("deposit crossed revocation commit", err)
	}
	a, _ := parseAgentText(f.r.agentID)
	if _, err = f.s.store.list(t.Context(), a, now, c); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatal("list crossed revocation commit", err)
	}
	if _, err = f.s.store.get(t.Context(), a, e.id, now, c); !errors.Is(err, ErrCredentialRevoked) {
		t.Fatal("fetch crossed revocation commit", err)
	}
}

func TestV2DirectoryAndLongPollTLSClient(t *testing.T) {
	f := newV2HTTP(t)
	f.s.directory = true
	server := httptest.NewTLSServer(f.s)
	defer server.Close()
	f.s.relay = server.URL
	c, err := agenttransport.DecodeCredential(f.wire)
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := c.Blocks()
	if err != nil {
		t.Fatal(err)
	}
	caveats := blocks[0].Caveats
	for i := range caveats {
		if caveats[i].Type == agenttransport.CaveatRelay {
			caveats[i] = agenttransport.RelayCaveat(server.URL)
		}
	}
	f.wire, err = agenttransport.IssueCredential(mustDelegation(t, c), v2TestKey("http-transport"), f.holder.Public().(ed25519.PublicKey), caveats)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewV2Client(server.URL, server.Client().Transport, f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	description, err := client.Describe(t.Context())
	if err != nil || !description.Directory || description.MaxWaitSeconds != 25 || description.StrangerMaxEnvelopes != 32 {
		t.Fatal(description, err)
	}
	raw, digest := directoryHint(t, f, 0)
	if err = client.PublishHint(t.Context(), raw); err != nil {
		t.Fatal(err)
	}
	index, err := client.HintIndex(t.Context(), f.r.agentID)
	if err != nil || len(index) != 1 || index[0].Digest != digest {
		t.Fatal(index, err)
	}
	fetched, err := client.HintRecord(t.Context(), f.r.agentID, digest)
	if err != nil || !bytes.Equal(fetched, raw) {
		t.Fatal(err)
	}
	if _, err = f.s.verifier.VerifyConsumerHint(t.Context(), fetched, agenttransport.HintPolicy{}, nil); err != nil {
		t.Fatal("consumer refused fetched hint", err)
	}
	started := make(chan struct{}, 1)
	ticks := make(chan time.Time, 1)
	installWaitClock(t, f, started, ticks)
	type answer struct {
		Entries []V2MailboxEntry
		Err     error
	}
	result := make(chan answer, 1)
	go func() {
		entries, err := client.ListWait(t.Context(), f.r.agentID, f.wire, f.holder, 25)
		result <- answer{entries, err}
	}()
	waitStarted(t, started)
	e := f.r.seal(t, testPacket(1), unixNow(f.clock.Now())+3600)
	if err = client.Deposit(t.Context(), e.envelope, nil, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-result:
		if got.Err != nil || len(got.Entries) != 1 {
			t.Fatal(got)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("client long poll did not wake")
	}
	// A fresh contact root can be revoked without revoking this owner root.
	contact, err := agenttransport.IssueCredential(mustDelegation(t, c), v2TestKey("http-transport"), f.holder.Public().(ed25519.PublicKey), []agenttransport.Caveat{agenttransport.NotBeforeCaveat(unixNow(f.clock.Now()) - 1), agenttransport.NotAfterCaveat(unixNow(f.clock.Now()) + 3600), agenttransport.OperationsCaveat(agenttransport.OperationDeposit), agenttransport.RelayCaveat(f.s.relay)})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := agenttransport.DecodeCredential(contact)
	if err != nil {
		t.Fatal(err)
	}
	chains, err := parsed.ChainValues()
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Revoke(t.Context(), f.r.agentID, []Revocation{{chains[1], unixNow(f.clock.Now()) + 3600}}, f.wire, f.holder); err != nil {
		t.Fatal(err)
	}
	next := f.r.seal(t, testPacket(2), unixNow(f.clock.Now())+3600)
	if err = client.Deposit(t.Context(), next.envelope, contact, f.holder); err == nil {
		t.Fatal("revoked contact accepted by TLS service")
	}
}
func TestV2DirectoryDropsAbsentAndTombstonedAgents(t *testing.T) {
	for _, kind := range []string{"absent", "tombstoned"} {
		t.Run(kind, func(t *testing.T) {
			f := newV2HTTP(t)
			raw, _ := directoryHint(t, f, 0)
			path := "/v2/hints/" + f.r.agentID
			f.serve(t, "PUT", path, raw, false, 204)
			if kind == "absent" {
				f.source.state = nil
			} else {
				f.source.state.GetAgent().Tombstoned = true
			}
			f.clock.at = f.clock.at.Add(300 * time.Second)
			f.serve(t, "GET", path, nil, false, 404)
			if len(f.s.store.hints) != 0 {
				t.Fatal("non-live Agent consumes a hint slot")
			}
		})
	}
}

func TestV2DirectoryPublicLookupRateAndAgentBinding(t *testing.T) {
	f := newV2HTTP(t)
	other := newRecipient(t)
	raw, _ := directoryHint(t, f, 0)
	f.serve(t, "PUT", "/v2/hints/"+other.agentID, raw, false, 403)
	for i := range 61 {
		want := 404
		if i == 60 {
			want = 429
		}
		f.serve(t, "GET", "/v2/hints/"+f.r.agentID, nil, false, want)
	}
	if len(f.s.store.hints) != 0 {
		t.Fatal("public misses allocate directory slots")
	}
}
func TestV2RevocationNeverShortensAndGlobalCountIsBounded(t *testing.T) {
	f := newV2HTTP(t)
	f.s.store.controlLimits.RevocationEntries = 1
	now := unixNow(f.clock.Now())
	checked := v2Checked(t, f.wire, f.holder, f.r.agentID, now, 120)
	key := [32]byte{1}
	for _, until := range []uint64{now + 3600, now + 1, now - 1} {
		if err := f.s.store.revoke(t.Context(), f.r.agentID, []Revocation{{key, until}}, checked, now); err != nil {
			t.Fatal(err)
		}
		if f.s.store.revocations[f.r.agentID][key] != now+3600 {
			t.Fatal("a replay shortened revocation")
		}
	}
	if err := f.s.store.revoke(t.Context(), f.r.agentID, []Revocation{{[32]byte{2}, now + 3600}}, checked, now); !errors.Is(err, errControlQuota) {
		t.Fatal("global revocation quota lost", err)
	}
}
func TestV2ControlOptionsRefuseBeforeOpeningStore(t *testing.T) {
	for _, options := range []V2OpenOptions{{DirectoryAgents: -1}, {DirectoryAgents: maxDirectoryAgents + 1}, {RevocationEntries: -1}, {RevocationEntries: maxRevocationEntries + 1}, {MaxWaiters: -1}, {MaxWaiters: 4097}} {
		path := filepath.Join(v2Temp(t), "unused")
		if _, err := OpenV2Store(path, DefaultV2Limits(1024, 64<<20), testStart, options); err == nil {
			t.Fatal("invalid control bounds accepted")
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid config touched storage", err)
		}
	}
}
func TestV2DirectoryControlCrashWorker(t *testing.T) {
	root := os.Getenv("V2_DIRECTORY_CRASH_ROOT")
	if root == "" {
		return
	}
	s := v2Open(t, root, DefaultV2Limits(1024, 64<<20), testStart)
	cut := func(name string) error {
		if strings.HasPrefix(name, "controls/") {
			os.Exit(29)
		}
		return nil
	}
	if os.Getenv("V2_DIRECTORY_CRASH_POINT") == "before-rename" {
		s.disk.beforeRename = cut
	} else {
		s.disk.beforeSync = cut
	}
	agent := os.Getenv("V2_DIRECTORY_CRASH_AGENT")
	if os.Getenv("V2_DIRECTORY_CRASH_KIND") == "revocation" {
		s.mu.Lock()
		err := s.writeRevocationsLocked(agent, map[[32]byte]uint64{{1}: uint64(testStart.Unix()) + 3600})
		s.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	} else {
		raw, err := hex.DecodeString(os.Getenv("V2_DIRECTORY_CRASH_HINT"))
		if err != nil {
			t.Fatal(err)
		}
		meta, err := hintMetadata(agent, raw)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := encodeV2(v2HintRecord{"tos.service.relay-hint.v2", agent, raw})
		if err != nil {
			t.Fatal(err)
		}
		if err = s.disk.write(hintName(agent, meta.Digest), encoded); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("crash cut not reached")
}
func TestV2DirectoryControlCrashCuts(t *testing.T) {
	for _, kind := range []string{"revocation", "hint"} {
		for _, point := range []string{"before-rename", "after-rename"} {
			t.Run(kind+"/"+point, func(t *testing.T) {
				f := newV2HTTP(t)
				raw, _ := directoryHint(t, f, 0)
				v2Close(t, f.s.store)
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestV2DirectoryControlCrashWorker$", "-test.count=1")
				cmd.Env = append(os.Environ(), "V2_DIRECTORY_CRASH_ROOT="+f.path, "V2_DIRECTORY_CRASH_POINT="+point, "V2_DIRECTORY_CRASH_AGENT="+f.r.agentID, "V2_DIRECTORY_CRASH_KIND="+kind, "V2_DIRECTORY_CRASH_HINT="+hex.EncodeToString(raw))
				err := cmd.Run()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 29 {
					t.Fatal("worker missed cut", err)
				}
				f.s.store = v2Open(t, f.path, DefaultV2Limits(1024, 64<<20), f.clock.Now())
				count := f.s.store.revocationCount
				if kind == "hint" {
					count = len(f.s.store.hints[f.r.agentID])
				}
				want := 0
				if point == "after-rename" {
					want = 1
				}
				if count != want {
					t.Fatal("crash lost or invented committed control", count, want)
				}
			})
		}
	}
}
func TestV2CorruptControlRefusesStartup(t *testing.T) {
	for _, kind := range []string{"hint", "revocation"} {
		t.Run(kind, func(t *testing.T) {
			f := newV2HTTP(t)
			name := ""
			if kind == "hint" {
				raw, digest := directoryHint(t, f, 0)
				f.serve(t, "PUT", "/v2/hints/"+f.r.agentID, raw, false, 204)
				name = hintName(f.r.agentID, digest)
			} else {
				checked := v2Checked(t, f.wire, f.holder, f.r.agentID, unixNow(f.clock.Now()), 120)
				if err := f.s.store.revoke(t.Context(), f.r.agentID, []Revocation{{[32]byte{1}, unixNow(f.clock.Now()) + 3600}}, checked, unixNow(f.clock.Now())); err != nil {
					t.Fatal(err)
				}
				name = revocationName(f.r.agentID)
			}
			v2Close(t, f.s.store)
			path := filepath.Join(f.path, name)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			raw[len(raw)/2] ^= 1
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			opened, err := OpenV2Store(f.path, DefaultV2Limits(1024, 64<<20), f.clock.Now(), V2OpenOptions{})
			if err == nil {
				v2Close(t, opened)
				t.Fatal("corrupt control accepted")
			}
		})
	}
}

func TestV2DirectoryKeepsNewestAndFreesRevokedSlots(t *testing.T) {
	f := newV2HTTP(t)
	path := "/v2/hints/" + f.r.agentID
	now := unixNow(f.clock.Now())
	first, digest := directoryHint(t, f, 0)
	f.serve(t, "PUT", path, first, false, 204)
	newer, _ := signedDirectoryHint(t, f, 0, now+1, now+21601, []string{f.s.relay})
	f.serve(t, "PUT", path, newer, false, 204)
	f.serve(t, "PUT", path, first, false, 204)
	w := f.serve(t, "GET", path+"/"+hex.EncodeToString(digest[:]), nil, false, 200)
	if !bytes.Equal(w.Body.Bytes(), newer) {
		t.Fatal("older hint overwrote newer hint")
	}
	for i := 1; i < 4; i++ {
		raw, _ := directoryHint(t, f, byte(i))
		f.serve(t, "PUT", path, raw, false, 204)
	}
	// Withdraw one live delegation, not the incoming one. Its slot must free.
	withdrawn := "sha256:" + hex.EncodeToString(digest[:])
	var kept []*nativev1.DelegationAdmissionV1
	for _, d := range f.source.state.GetAgent().DelegationAdmissions {
		if d.Digest != withdrawn {
			kept = append(kept, d)
		}
	}
	f.source.state.GetAgent().DelegationAdmissions = kept
	f.clock.at = f.clock.at.Add(300 * time.Second)
	incoming, _ := directoryHint(t, f, 4)
	f.serve(t, "PUT", path, incoming, false, 204)
	if len(f.s.store.hints[f.r.agentID]) != 4 {
		t.Fatal("slot accounting drift")
	}
}
func TestV2DirectoryReadOutageDoesNotEvictLiveSlots(t *testing.T) {
	f := newV2HTTP(t)
	path := "/v2/hints/" + f.r.agentID
	for i := range 4 {
		raw, _ := directoryHint(t, f, byte(i))
		f.serve(t, "PUT", path, raw, false, 204)
	}
	f.source.err = agenttransport.ErrUnavailable
	f.clock.at = f.clock.at.Add(600 * time.Second)
	f.serve(t, "GET", path, nil, false, 503)
	if len(f.s.store.hints[f.r.agentID]) != 4 {
		t.Fatal("outage evicted a live record")
	}
	f.source.err = nil
	raw, _ := directoryHint(t, f, 4)
	f.serve(t, "PUT", path, raw, false, 507)
}
func TestV2DirectoryRefusesUnadmittedDelegation(t *testing.T) {
	f := newV2HTTP(t)
	raw, _ := directoryHint(t, f, 0)
	f.source.state.GetAgent().DelegationAdmissions = nil
	f.serve(t, "PUT", "/v2/hints/"+f.r.agentID, raw, false, 403)
	if len(f.s.store.hints) != 0 {
		t.Fatal("unadmitted transport key acquired storage")
	}
}
func TestV2RevocationIsCheckedBeforeFinalizedRead(t *testing.T) {
	f := newV2HTTP(t)
	c, err := agenttransport.DecodeCredential(f.wire)
	if err != nil {
		t.Fatal(err)
	}
	chains, err := c.ChainValues()
	if err != nil {
		t.Fatal(err)
	}
	f.s.store.mu.Lock()
	err = f.s.store.writeRevocationsLocked(f.r.agentID, map[[32]byte]uint64{chains[1]: unixNow(f.clock.Now()) + 3600})
	f.s.store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	f.source.err = agenttransport.ErrUnavailable
	f.serve(t, "GET", f.mail(), nil, true, 403)
	if f.source.reads != 0 {
		t.Fatal("revoked credential forced a finalized read")
	}
}

func TestV2DescriptionRequiresEveryField(t *testing.T) {
	f := newV2HTTP(t)
	handler := f.s
	recorder := httptest.NewRecorder()
	handler.describeV2(recorder)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(recorder.Body.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	check := func(t *testing.T, body []byte, valid bool) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", ContentTypeJSON)
			_, _ = w.Write(body)
		}))
		defer server.Close()
		client, err := NewV2Client(server.URL, server.Client().Transport, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Describe(context.Background())
		if (err == nil) != valid {
			t.Fatalf("valid=%v err=%v", valid, err)
		}
	}
	check(t, recorder.Body.Bytes(), true)
	for key, value := range fields {
		t.Run(key+"-missing", func(t *testing.T) {
			delete(fields, key)
			body, err := json.Marshal(fields)
			fields[key] = value
			if err != nil {
				t.Fatal(err)
			}
			check(t, body, false)
		})
		t.Run(key+"-null", func(t *testing.T) {
			fields[key] = json.RawMessage("null")
			body, err := json.Marshal(fields)
			fields[key] = value
			if err != nil {
				t.Fatal(err)
			}
			check(t, body, false)
		})
	}
}
