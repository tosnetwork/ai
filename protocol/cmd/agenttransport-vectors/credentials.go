package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

const credentialSchema = "tos.agent-transport-credential-v1.vectors"

// Times are fixed so every vector reproduces.
const (
	baseTime = 1800000000
	nowTime  = baseTime + 100
)

type keyVector struct {
	Name   string `json:"name"`
	Seed   string `json:"seed"`
	Public string `json:"public"`
}

type delegationVector struct {
	Name       string `json:"name"`
	Agent      string `json:"agent_digest"`
	Key        string `json:"transport_key"`
	Epoch      uint64 `json:"epoch"`
	Policy     string `json:"policy_hash"`
	Purposes   byte   `json:"purposes"`
	Before     uint64 `json:"not_before"`
	After      uint64 `json:"not_after"`
	Credential uint32 `json:"max_credential_seconds"`
	Wire       string `json:"wire"`
	Digest     string `json:"digest"`
}

// caveatVector carries a typed value: integers for numeric caveats, a string
// for the relay URL and hex for the lane.
type caveatVector struct {
	Type  string `json:"type"`
	Value any    `json:"value"`
}

type blockVector struct {
	Signer  string         `json:"signer"`
	Next    string         `json:"next"`
	Caveats []caveatVector `json:"caveats"`
}

type credentialVector struct {
	Name         string        `json:"name"`
	Delegation   string        `json:"delegation"`
	Blocks       []blockVector `json:"blocks"`
	Chain        []string      `json:"chain"`
	CredentialID string        `json:"credential_id"`
	Holder       string        `json:"holder"`
	Length       int           `json:"length"`
	Wire         string        `json:"wire"`
}

type usageVector struct {
	StoredEnvelopes uint64 `json:"stored_envelopes"`
	StoredBytes     uint64 `json:"stored_bytes"`
	EnvelopeBytes   uint64 `json:"envelope_bytes"`
}

type evaluationVector struct {
	Name       string       `json:"name"`
	Credential string       `json:"credential"`
	Now        uint64       `json:"now"`
	RelayURL   string       `json:"relay_url"`
	Operation  string       `json:"operation"`
	Usage      *usageVector `json:"usage,omitempty"`
	Expect     string       `json:"expect"`
}

type proofVector struct {
	Name             string `json:"name"`
	Credential       string `json:"credential"`
	Signer           string `json:"signer"`
	Agent            string `json:"agent"`
	Operation        string `json:"operation"`
	RelayURL         string `json:"relay_url"`
	Method           string `json:"method"`
	Path             string `json:"path"`
	Body             string `json:"body"`
	IssuedAt         uint64 `json:"issued_at"`
	Nonce            string `json:"nonce"`
	Now              uint64 `json:"now"`
	Preimage         string `json:"preimage,omitempty"`
	Signature        string `json:"signature,omitempty"`
	CredentialHeader string `json:"credential_header"`
	ProofHeader      string `json:"proof_header"`
	Expect           string `json:"expect"`
}

type negativeCredential struct {
	Name  string `json:"name"`
	Stage string `json:"stage"`
	Class string `json:"class"`
	Wire  string `json:"wire"`
}

type credentialCorpus struct {
	Schema       string               `json:"schema"`
	Keys         []keyVector          `json:"keys"`
	Delegations  []delegationVector   `json:"delegations"`
	Credentials  []credentialVector   `json:"credentials"`
	Evaluations  []evaluationVector   `json:"evaluations"`
	Proofs       []proofVector        `json:"proofs"`
	NegativeWire []negativeCredential `json:"negative_credentials"`
}

type generator struct {
	out         credentialCorpus
	keys        map[string]ed25519.PrivateKey
	delegations map[string][]byte
	credentials map[string][]byte
}

func (g *generator) key(name string) ed25519.PrivateKey {
	if k, ok := g.keys[name]; ok {
		return k
	}
	seed := sha256.Sum256([]byte("credential-vector-key-" + name))
	k := ed25519.NewKeyFromSeed(seed[:])
	g.keys[name] = k
	g.out.Keys = append(g.out.Keys, keyVector{Name: name, Seed: hex.EncodeToString(seed[:]), Public: hex.EncodeToString(k.Public().(ed25519.PublicKey))})
	return k
}

func (g *generator) public(name string) ed25519.PublicKey {
	return g.key(name).Public().(ed25519.PublicKey)
}

func (g *generator) delegation(name, key string, epoch uint64, purposes byte, maxCredential uint32) error {
	d := agenttransport.Delegation{
		AgentDigest:          sha256.Sum256([]byte("credential-vector-agent-" + name)),
		AuthorizationEpoch:   epoch,
		PolicyHash:           sha256.Sum256([]byte("credential-vector-policy-" + name)),
		Purposes:             agenttransport.Purpose(purposes),
		NotBefore:            baseTime - 86400,
		NotAfter:             baseTime + 86400*30,
		MaxCredentialSeconds: maxCredential,
	}
	copy(d.TransportKey[:], g.public(key))
	b, err := d.Encode()
	if err != nil {
		return err
	}
	digest := sha256.Sum256(b)
	g.delegations[name] = b
	g.out.Delegations = append(g.out.Delegations, delegationVector{Name: name, Agent: hex.EncodeToString(d.AgentDigest[:]), Key: hex.EncodeToString(d.TransportKey[:]), Epoch: epoch, Policy: hex.EncodeToString(d.PolicyHash[:]), Purposes: purposes, Before: d.NotBefore, After: d.NotAfter, Credential: maxCredential, Wire: hex.EncodeToString(b), Digest: hex.EncodeToString(digest[:])})
	return nil
}

var caveatNames = map[agenttransport.CaveatType]string{
	agenttransport.CaveatNotBefore: "not_before", agenttransport.CaveatNotAfter: "not_after",
	agenttransport.CaveatRelay: "relay", agenttransport.CaveatOperations: "operations",
	agenttransport.CaveatLane: "lane", agenttransport.CaveatMaxEnvelopes: "max_envelopes",
	agenttransport.CaveatMaxEnvelopeBytes: "max_envelope_bytes", agenttransport.CaveatMaxLaneBytes: "max_lane_bytes",
}

func describe(c agenttransport.Caveat) (caveatVector, error) {
	name, ok := caveatNames[c.Type]
	if !ok {
		return caveatVector{}, fmt.Errorf("unknown caveat %d", c.Type)
	}
	switch c.Type {
	case agenttransport.CaveatRelay:
		return caveatVector{Type: name, Value: string(c.Value)}, nil
	case agenttransport.CaveatLane:
		return caveatVector{Type: name, Value: hex.EncodeToString(c.Value)}, nil
	case agenttransport.CaveatOperations:
		return caveatVector{Type: name, Value: uint64(binary.BigEndian.Uint16(c.Value))}, nil
	case agenttransport.CaveatMaxEnvelopes, agenttransport.CaveatMaxEnvelopeBytes:
		return caveatVector{Type: name, Value: uint64(binary.BigEndian.Uint32(c.Value))}, nil
	default:
		return caveatVector{Type: name, Value: binary.BigEndian.Uint64(c.Value)}, nil
	}
}

type step struct {
	signer, next string
	caveats      []agenttransport.Caveat
}

// credential builds through the package builders, so positive bytes are the
// implementation's own output.
func (g *generator) credential(name, delegation string, steps ...step) error {
	var wire []byte
	var err error
	v := credentialVector{Name: name, Delegation: delegation}
	for i, s := range steps {
		if i == 0 {
			wire, err = agenttransport.IssueCredential(g.delegations[delegation], g.key(s.signer), g.public(s.next), s.caveats)
		} else {
			wire, err = agenttransport.AppendCredentialBlock(wire, g.key(s.signer), g.public(s.next), s.caveats)
		}
		if err != nil {
			return fmt.Errorf("%s block %d: %w", name, i, err)
		}
		b := blockVector{Signer: s.signer, Next: s.next}
		c, err := agenttransport.DecodeCredential(wire)
		if err != nil {
			return err
		}
		blocks, err := c.Blocks()
		if err != nil {
			return err
		}
		for _, cv := range blocks[i].Caveats {
			d, err := describe(cv)
			if err != nil {
				return err
			}
			b.Caveats = append(b.Caveats, d)
		}
		v.Blocks = append(v.Blocks, b)
	}
	return g.record(v, wire)
}

func (g *generator) record(v credentialVector, wire []byte) error {
	c, err := agenttransport.DecodeCredential(wire)
	if err != nil {
		return err
	}
	if err = c.VerifyChain(); err != nil {
		return err
	}
	chain, err := c.ChainValues()
	if err != nil {
		return err
	}
	for _, value := range chain {
		v.Chain = append(v.Chain, hex.EncodeToString(value[:]))
	}
	id, err := c.CredentialID()
	if err != nil {
		return err
	}
	holder, err := c.HolderKey()
	if err != nil {
		return err
	}
	v.CredentialID, v.Holder, v.Length, v.Wire = hex.EncodeToString(id[:]), hex.EncodeToString(holder[:]), len(wire), hex.EncodeToString(wire)
	g.credentials[v.Name] = wire
	g.out.Credentials = append(g.out.Credentials, v)
	return nil
}

// rawCredential signs blocks with BlockSigningPreimage, bypassing the
// builder's lane check, for the decode-valid lane-conflict vector.
func (g *generator) rawCredential(name, delegation string, steps ...step) error {
	del := g.delegations[delegation]
	var blocks []agenttransport.Block
	v := credentialVector{Name: name, Delegation: delegation}
	for _, s := range steps {
		b := agenttransport.Block{Caveats: s.caveats}
		copy(b.NextPublicKey[:], g.public(s.next))
		preimage, err := agenttransport.BlockSigningPreimage(del, blocks, b)
		if err != nil {
			return err
		}
		copy(b.Signature[:], ed25519.Sign(g.key(s.signer), preimage))
		blocks = append(blocks, b)
		bv := blockVector{Signer: s.signer, Next: s.next}
		for _, cv := range s.caveats {
			d, err := describe(cv)
			if err != nil {
				return err
			}
			bv.Caveats = append(bv.Caveats, d)
		}
		v.Blocks = append(v.Blocks, bv)
	}
	c, err := agenttransport.NewCredential(del, blocks)
	if err != nil {
		return err
	}
	wire, err := c.Encode()
	if err != nil {
		return err
	}
	return g.record(v, wire)
}

var operationNames = map[string]agenttransport.Operation{
	"deposit": agenttransport.OperationDeposit, "list": agenttransport.OperationList,
	"fetch": agenttransport.OperationFetch, "publish": agenttransport.OperationPublish,
	"revoke": agenttransport.OperationRevoke,
}

func (g *generator) evaluate(name, credential string, now uint64, relay, op string, usage *usageVector) error {
	c, err := agenttransport.DecodeCredential(g.credentials[credential])
	if err != nil {
		return err
	}
	err = c.CheckScope(now, relay, operationNames[op])
	if err == nil && usage != nil {
		err = c.CheckDeposit(agenttransport.LaneUsage{StoredEnvelopes: usage.StoredEnvelopes, StoredBytes: usage.StoredBytes, EnvelopeBytes: usage.EnvelopeBytes})
	}
	expect := "accept"
	if err != nil {
		if !errors.Is(err, agenttransport.ErrCredentialScope) {
			return fmt.Errorf("evaluation %s: unexpected class: %w", name, err)
		}
		expect = "credential_scope"
	}
	g.out.Evaluations = append(g.out.Evaluations, evaluationVector{Name: name, Credential: credential, Now: now, RelayURL: relay, Operation: op, Usage: usage, Expect: expect})
	return nil
}

type proofCase struct {
	name, credential, signer, op string
	request                      agenttransport.ProofRequest
	issuedAt, now                uint64
	agent                        string
	mutateProof                  func(string) string
	mutateCredential             func(string) string
	verifyRequest                *agenttransport.ProofRequest
}

func nonceFor(name string) [32]byte { return sha256.Sum256([]byte("credential-vector-nonce-" + name)) }

func (g *generator) proof(pc proofCase) error {
	wire := g.credentials[pc.credential]
	c, err := agenttransport.DecodeCredential(wire)
	if err != nil {
		return err
	}
	nonce := nonceFor(pc.name)
	id, err := c.CredentialID()
	if err != nil {
		return err
	}
	preimage, err := agenttransport.ProofPreimage(id, pc.request, pc.issuedAt, nonce)
	if err != nil {
		return err
	}
	p := agenttransport.Proof{IssuedAt: pc.issuedAt, Nonce: nonce}
	copy(p.Signature[:], ed25519.Sign(g.key(pc.signer), preimage))
	v := proofVector{Name: pc.name, Credential: pc.credential, Signer: pc.signer, Operation: pc.op, IssuedAt: pc.issuedAt, Nonce: hex.EncodeToString(nonce[:]), Now: pc.now,
		CredentialHeader: agenttransport.EncodeCredentialHeader(wire), ProofHeader: p.Header()}
	d, err := c.Delegation()
	if err != nil {
		return err
	}
	v.Agent = d.AgentID()
	if pc.agent != "" {
		v.Agent = pc.agent
	}
	verify := pc.request
	if pc.verifyRequest != nil {
		verify = *pc.verifyRequest
	} else {
		v.Preimage, v.Signature = hex.EncodeToString(preimage), hex.EncodeToString(p.Signature[:])
	}
	v.RelayURL, v.Method, v.Path, v.Body = verify.RelayURL, verify.Method, verify.Path, hex.EncodeToString(verify.Body)
	if pc.mutateProof != nil {
		v.ProofHeader = pc.mutateProof(v.ProofHeader)
	}
	if pc.mutateCredential != nil {
		v.CredentialHeader = pc.mutateCredential(v.CredentialHeader)
	}
	_, err = agenttransport.CheckRequest(agenttransport.Request{AgentID: v.Agent, Operation: operationNames[pc.op], Proof: verify, CredentialValue: v.CredentialHeader, ProofValue: v.ProofHeader, Now: pc.now})
	switch {
	case err == nil:
		v.Expect = "accept"
	case errors.Is(err, agenttransport.ErrCredentialInvalid):
		v.Expect = "credential_invalid"
	case errors.Is(err, agenttransport.ErrCredentialScope):
		v.Expect = "credential_scope"
	default:
		return fmt.Errorf("proof %s: unexpected class: %w", pc.name, err)
	}
	if v.Expect != "accept" {
		v.Preimage, v.Signature = "", ""
	}
	g.out.Proofs = append(g.out.Proofs, v)
	return nil
}

// rawBlock encodes a block with no validation, for negative mutations only.
type rawCaveat struct {
	t     byte
	value []byte
}

func rawBlockBytes(next []byte, count int, caveats []rawCaveat, sig []byte) []byte {
	var body []byte
	body = append(body, next...)
	body = append(body, byte(count))
	for _, c := range caveats {
		body = append(body, c.t)
		body = binary.BigEndian.AppendUint16(body, uint16(len(c.value)))
		body = append(body, c.value...)
	}
	body = append(body, sig...)
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...)
}

func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

func (g *generator) negative(name, stage string, wire []byte) error {
	c, err := agenttransport.DecodeCredential(wire)
	if stage == "decode" && err == nil {
		return fmt.Errorf("negative %s decoded", name)
	}
	if stage == "chain" {
		if err != nil {
			return fmt.Errorf("negative %s should decode: %w", name, err)
		}
		err = c.VerifyChain()
		if err == nil {
			return fmt.Errorf("negative %s verified", name)
		}
	}
	if !errors.Is(err, agenttransport.ErrCredentialInvalid) {
		return fmt.Errorf("negative %s has the wrong class: %w", name, err)
	}
	g.out.NegativeWire = append(g.out.NegativeWire, negativeCredential{Name: name, Stage: stage, Class: "credential_invalid", Wire: hex.EncodeToString(wire)})
	return nil
}

const (
	relayA = "https://relay-a.example"
	relayB = "https://relay-b.example"
	allOps = agenttransport.OperationDeposit | agenttransport.OperationList | agenttransport.OperationFetch | agenttransport.OperationPublish | agenttransport.OperationRevoke
	owner  = agenttransport.OperationList | agenttransport.OperationFetch | agenttransport.OperationPublish | agenttransport.OperationRevoke
)

func lane(tag string) [16]byte {
	h := sha256.Sum256([]byte("credential-vector-lane-" + tag))
	return [16]byte(h[:16])
}

func maximalRelay(tag string) string {
	prefix := "https://" + tag + ".example/"
	return prefix + strings.Repeat("p", agenttransport.MaxRelayURLBytes-len(prefix))
}

func allCaveats(nb, na uint64, relay string, ops agenttransport.Operation, l [16]byte, envelopes, envelopeBytes uint32, laneBytes uint64) []agenttransport.Caveat {
	return []agenttransport.Caveat{
		agenttransport.NotBeforeCaveat(nb), agenttransport.NotAfterCaveat(na), agenttransport.RelayCaveat(relay),
		agenttransport.OperationsCaveat(ops), agenttransport.LaneCaveat(l), agenttransport.MaxEnvelopesCaveat(envelopes),
		agenttransport.MaxEnvelopeBytesCaveat(envelopeBytes), agenttransport.MaxLaneBytesCaveat(laneBytes),
	}
}

func (g *generator) build() error {
	if err := g.delegation("owner", "transport-owner", 0, 1, 3600); err != nil {
		return err
	}
	if err := g.delegation("contact", "transport-contact", 7, 7, agenttransport.MaxCredentialSeconds); err != nil {
		return err
	}
	// The same transport key under another epoch: chain_0 binds the delegation.
	if err := g.delegation("contact-rotated", "transport-contact", 8, 7, agenttransport.MaxCredentialSeconds); err != nil {
		return err
	}
	ownerCaveats := []agenttransport.Caveat{agenttransport.NotBeforeCaveat(baseTime), agenttransport.NotAfterCaveat(baseTime + 3600), agenttransport.OperationsCaveat(owner)}
	if err := g.credential("owner", "owner", step{"transport-owner", "holder-owner", ownerCaveats}); err != nil {
		return err
	}
	contactCaveats := []agenttransport.Caveat{
		agenttransport.NotBeforeCaveat(baseTime), agenttransport.NotAfterCaveat(baseTime + 259200),
		agenttransport.OperationsCaveat(agenttransport.OperationDeposit), agenttransport.LaneCaveat(lane("contact")),
		agenttransport.MaxEnvelopesCaveat(64), agenttransport.MaxEnvelopeBytesCaveat(agenttransport.MaxEnvelopeBytes),
	}
	if err := g.credential("contact", "contact", step{"transport-contact", "holder-contact", contactCaveats}); err != nil {
		return err
	}
	if err := g.credential("contact-relay-scoped", "contact",
		step{"transport-contact", "holder-contact", contactCaveats},
		step{"holder-contact", "holder-contact", []agenttransport.Caveat{agenttransport.RelayCaveat(relayA)}}); err != nil {
		return err
	}
	// Every later block tries to widen what block 0 grants.
	if err := g.credential("widening-attempt", "contact",
		step{"transport-contact", "holder-1", []agenttransport.Caveat{
			agenttransport.NotBeforeCaveat(baseTime), agenttransport.NotAfterCaveat(baseTime + 3600),
			agenttransport.RelayCaveat(relayA), agenttransport.OperationsCaveat(agenttransport.OperationDeposit),
			agenttransport.MaxEnvelopesCaveat(2), agenttransport.MaxEnvelopeBytesCaveat(1024), agenttransport.MaxLaneBytesCaveat(2048)}},
		step{"holder-1", "holder-2", []agenttransport.Caveat{
			agenttransport.NotBeforeCaveat(baseTime - 86400), agenttransport.NotAfterCaveat(baseTime + 604800),
			agenttransport.RelayCaveat(relayA), agenttransport.OperationsCaveat(allOps),
			agenttransport.MaxEnvelopesCaveat(64), agenttransport.MaxEnvelopeBytesCaveat(agenttransport.MaxEnvelopeBytes), agenttransport.MaxLaneBytesCaveat(1 << 40)}}); err != nil {
		return err
	}
	// A later block naming another relay leaves the credential usable nowhere.
	if err := g.credential("relay-conflict", "contact",
		step{"transport-contact", "holder-1", []agenttransport.Caveat{
			agenttransport.NotBeforeCaveat(baseTime), agenttransport.NotAfterCaveat(baseTime + 3600),
			agenttransport.RelayCaveat(relayA), agenttransport.OperationsCaveat(agenttransport.OperationDeposit)}},
		step{"holder-1", "holder-2", []agenttransport.Caveat{agenttransport.RelayCaveat(relayB)}}); err != nil {
		return err
	}
	if err := g.credential("narrowing", "contact",
		step{"transport-contact", "holder-1", []agenttransport.Caveat{
			agenttransport.NotBeforeCaveat(baseTime), agenttransport.NotAfterCaveat(baseTime + 3600), agenttransport.OperationsCaveat(allOps)}},
		step{"holder-1", "holder-2", []agenttransport.Caveat{agenttransport.NotAfterCaveat(baseTime + 600), agenttransport.OperationsCaveat(agenttransport.OperationDeposit | agenttransport.OperationList)}},
		step{"holder-2", "holder-3", []agenttransport.Caveat{agenttransport.NotBeforeCaveat(baseTime + 200), agenttransport.OperationsCaveat(agenttransport.OperationDeposit)}}); err != nil {
		return err
	}
	maximal := func(name, tag string, ops agenttransport.Operation) error {
		var steps []step
		signer := "transport-contact"
		for i := range agenttransport.MaxCredentialBlocks {
			next := fmt.Sprintf("holder-%d", i+1)
			steps = append(steps, step{signer, next, allCaveats(baseTime+uint64(i), baseTime+604800-uint64(i), maximalRelay(tag), ops, lane("maximal"), uint32(64-i), uint32(agenttransport.MaxEnvelopeBytes-i), uint64(1<<30)-uint64(i))})
			signer = next
		}
		return g.credential(name, "contact", steps...)
	}
	if err := maximal("maximal", "relay-max", allOps); err != nil {
		return err
	}
	if err := maximal("maximal-sibling", "relay-sib", agenttransport.OperationDeposit); err != nil {
		return err
	}
	if err := g.rawCredential("lane-conflict", "contact",
		step{"transport-contact", "holder-1", []agenttransport.Caveat{agenttransport.NotBeforeCaveat(baseTime), agenttransport.NotAfterCaveat(baseTime + 3600), agenttransport.OperationsCaveat(agenttransport.OperationDeposit), agenttransport.LaneCaveat(lane("a"))}},
		step{"holder-1", "holder-2", []agenttransport.Caveat{agenttransport.LaneCaveat(lane("b"))}}); err != nil {
		return err
	}
	if n := len(g.credentials["maximal"]); n != 1916 {
		return fmt.Errorf("maximal credential is %d bytes, want 1916", n)
	}
	if err := g.evaluations(); err != nil {
		return err
	}
	if err := g.proofs(); err != nil {
		return err
	}
	return g.negatives()
}

func (g *generator) evaluations() error {
	type e struct {
		name, credential string
		now              uint64
		relay, op        string
		usage            *usageVector
	}
	for _, c := range []e{
		{"owner-list", "owner", nowTime, relayA, "list", nil},
		{"owner-revoke", "owner", nowTime, relayA, "revoke", nil},
		{"owner-deposit-not-granted", "owner", nowTime, relayA, "deposit", nil},
		{"owner-not-before-edge", "owner", baseTime - 300, relayA, "list", nil},
		{"owner-not-before-early", "owner", baseTime - 301, relayA, "list", nil},
		{"owner-last-second", "owner", baseTime + 3599, relayA, "list", nil},
		{"owner-expired", "owner", baseTime + 3600, relayA, "list", nil},
		{"contact-deposit-any-relay", "contact", nowTime, relayB, "deposit", &usageVector{0, 0, 1}},
		{"contact-deposit-max-envelope", "contact", nowTime, relayA, "deposit", &usageVector{63, 0, 262144}},
		{"contact-lane-full", "contact", nowTime, relayA, "deposit", &usageVector{64, 0, 1}},
		{"contact-list-not-granted", "contact", nowTime, relayA, "list", nil},
		{"scoped-at-its-relay", "contact-relay-scoped", nowTime, relayA, "deposit", &usageVector{0, 0, 100}},
		{"scoped-at-another-relay", "contact-relay-scoped", nowTime, relayB, "deposit", nil},
		{"widening-relay-a", "widening-attempt", nowTime, relayA, "deposit", nil},
		{"widening-relay-b", "widening-attempt", nowTime, relayB, "deposit", nil},
		{"relay-conflict-a", "relay-conflict", nowTime, relayA, "deposit", nil},
		{"relay-conflict-b", "relay-conflict", nowTime, relayB, "deposit", nil},
		{"widening-operation", "widening-attempt", nowTime, relayA, "list", nil},
		{"widening-later-expiry", "widening-attempt", baseTime + 3600, relayA, "deposit", nil},
		{"widening-earlier-start", "widening-attempt", baseTime - 301, relayA, "deposit", nil},
		{"widening-envelopes-edge", "widening-attempt", nowTime, relayA, "deposit", &usageVector{1, 0, 1}},
		{"widening-envelopes", "widening-attempt", nowTime, relayA, "deposit", &usageVector{2, 0, 1}},
		{"widening-envelope-bytes-edge", "widening-attempt", nowTime, relayA, "deposit", &usageVector{0, 0, 1024}},
		{"widening-envelope-bytes", "widening-attempt", nowTime, relayA, "deposit", &usageVector{0, 0, 1025}},
		{"widening-lane-bytes-edge", "widening-attempt", nowTime, relayA, "deposit", &usageVector{1, 1024, 1024}},
		{"widening-lane-bytes", "widening-attempt", nowTime, relayA, "deposit", &usageVector{1, 1025, 1024}},
		{"narrowing-deposit", "narrowing", baseTime + 200, relayA, "deposit", nil},
		{"narrowing-list", "narrowing", baseTime + 200, relayA, "list", nil},
		{"narrowing-before-start", "narrowing", baseTime - 101, relayA, "deposit", nil},
		{"narrowing-after-expiry", "narrowing", baseTime + 600, relayA, "deposit", nil},
		{"maximal-deposit", "maximal", nowTime, maximalRelay("relay-max"), "deposit", &usageVector{60, 0, 262141}},
		{"maximal-envelopes", "maximal", nowTime, maximalRelay("relay-max"), "deposit", &usageVector{61, 0, 1}},
		{"lane-conflict", "lane-conflict", nowTime, relayA, "deposit", nil},
	} {
		if err := g.evaluate(c.name, c.credential, c.now, c.relay, c.op, c.usage); err != nil {
			return err
		}
	}
	return nil
}

func (g *generator) proofs() error {
	list := agenttransport.ProofRequest{RelayURL: relayA, Method: "GET", Path: "/v2/mailboxes/" + "AGENT" + "/envelopes"}
	ownerAgent, err := agenttransport.DecodeDelegation(g.delegations["owner"])
	if err != nil {
		return err
	}
	list.Path = "/v2/mailboxes/" + ownerAgent.AgentID() + "/envelopes"
	contactAgent, err := agenttransport.DecodeDelegation(g.delegations["contact"])
	if err != nil {
		return err
	}
	deposit := agenttransport.ProofRequest{RelayURL: relayA, Method: "PUT", Path: "/v2/mailboxes/" + contactAgent.AgentID() + "/envelopes/" + strings.Repeat("ab", 32), Body: []byte("sealed envelope bytes")}
	other := func(change func(*agenttransport.ProofRequest)) *agenttransport.ProofRequest {
		r := list
		change(&r)
		return &r
	}
	flip := func(index int) func(string) string {
		return func(s string) string {
			p, err := agenttransport.DecodeProofHeader(s)
			if err != nil {
				return s
			}
			p.Signature[index%64] ^= 1
			return p.Header()
		}
	}
	cases := []proofCase{
		{name: "owner-list", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime, now: nowTime},
		{name: "owner-window-ahead", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime + 120, now: nowTime},
		{name: "owner-window-behind", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime - 120, now: nowTime},
		{name: "contact-deposit", credential: "contact-relay-scoped", signer: "holder-contact", op: "deposit", request: deposit, issuedAt: nowTime, now: nowTime},
		{name: "maximal-deposit", credential: "maximal", signer: "holder-4", op: "deposit", request: agenttransport.ProofRequest{RelayURL: maximalRelay("relay-max"), Method: "PUT", Path: deposit.Path, Body: deposit.Body}, issuedAt: nowTime, now: nowTime},
		{name: "too-far-ahead", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime + 121, now: nowTime},
		{name: "too-far-behind", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime - 121, now: nowTime},
		{name: "signed-by-transport-key", credential: "owner", signer: "transport-owner", op: "list", request: list, issuedAt: nowTime, now: nowTime},
		{name: "signed-by-earlier-holder", credential: "maximal", signer: "holder-3", op: "deposit", request: agenttransport.ProofRequest{RelayURL: maximalRelay("relay-max"), Method: "PUT", Path: deposit.Path, Body: deposit.Body}, issuedAt: nowTime, now: nowTime},
		{name: "other-relay", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime, now: nowTime, verifyRequest: other(func(r *agenttransport.ProofRequest) { r.RelayURL = relayB })},
		{name: "other-method", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime, now: nowTime, verifyRequest: other(func(r *agenttransport.ProofRequest) { r.Method = "PUT" })},
		{name: "other-path", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime, now: nowTime, verifyRequest: other(func(r *agenttransport.ProofRequest) { r.Path += "/x" })},
		{name: "other-body", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime, now: nowTime, verifyRequest: other(func(r *agenttransport.ProofRequest) { r.Body = []byte{0} })},
		{name: "path-with-query", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime, now: nowTime, verifyRequest: other(func(r *agenttransport.ProofRequest) { r.Path += "?a=1" })},
		{name: "flipped-signature", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime, now: nowTime, mutateProof: flip(5)},
		{name: "proof-padded", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime, now: nowTime, mutateProof: func(s string) string { return s + "==" }},
		{name: "proof-line-break", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime, now: nowTime, mutateProof: func(s string) string { return s[:10] + "\n" + s[10:] }},
		{name: "proof-short", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime, now: nowTime, mutateProof: func(s string) string { return s[:136] }},
		{name: "proof-time-altered", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime, now: nowTime, mutateProof: func(s string) string {
			p, err := agenttransport.DecodeProofHeader(s)
			if err != nil {
				return s
			}
			p.IssuedAt++
			return p.Header()
		}},
		{name: "proof-nonce-altered", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime, now: nowTime, mutateProof: func(s string) string {
			p, err := agenttransport.DecodeProofHeader(s)
			if err != nil {
				return s
			}
			p.Nonce[0] ^= 1
			return p.Header()
		}},
		{name: "credential-header-noncanonical", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime, now: nowTime, mutateCredential: func(s string) string {
			// The last character carries unused low bits; setting one is a second spelling.
			last := strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", s[len(s)-1])
			return s[:len(s)-1] + string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[last|1])
		}},
		{name: "other-agent", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: nowTime, now: nowTime, agent: contactAgent.AgentID()},
		{name: "operation-not-granted", credential: "owner", signer: "holder-owner", op: "deposit", request: list, issuedAt: nowTime, now: nowTime},
		{name: "credential-expired", credential: "owner", signer: "holder-owner", op: "list", request: list, issuedAt: baseTime + 3600, now: baseTime + 3600},
	}
	for _, pc := range cases {
		if err := g.proof(pc); err != nil {
			return err
		}
	}
	return nil
}

func (g *generator) negatives() error {
	contact := g.credentials["contact"]
	maximal := g.credentials["maximal"]
	sibling := g.credentials["maximal-sibling"]
	headerEnd := 32 + agenttransport.DelegationSize + 1
	header := func(count byte) []byte {
		h := append([]byte{}, contact[:headerEnd]...)
		h[headerEnd-1] = count
		return h
	}
	next := g.public("holder-contact")
	sig := make([]byte, 64)
	okBlock0 := []rawCaveat{{1, u64(baseTime)}, {2, u64(baseTime + 3600)}, {4, u16(1)}}
	withCaveats := func(caveats ...rawCaveat) []byte {
		return append(header(1), rawBlockBytes(next, len(caveats), caveats, sig)...)
	}
	extra := func(c rawCaveat) []byte { return withCaveats(append(append([]rawCaveat{}, okBlock0...), c)...) }
	mutate := func(src []byte, change func([]byte) []byte) []byte { return change(append([]byte{}, src...)) }
	small := make([]byte, 32)
	small[0] = 1
	noncanonical := make([]byte, 32)
	for i := range noncanonical {
		noncanonical[i] = 0xff
	}
	noncanonical[0], noncanonical[31] = 0xf0, 0x7f
	decoded, err := agenttransport.DecodeCredential(maximal)
	if err != nil {
		return err
	}
	blocks := make([][]byte, 0, 4)
	offset := headerEnd
	decodedBlocks, err := decoded.Blocks()
	if err != nil {
		return err
	}
	for range decodedBlocks {
		length := int(binary.BigEndian.Uint16(maximal[offset:]))
		blocks = append(blocks, maximal[offset:offset+2+length])
		offset += 2 + length
	}
	sibOffset := headerEnd + 2 + int(binary.BigEndian.Uint16(sibling[headerEnd:]))
	sibBlock1 := sibling[sibOffset : sibOffset+2+int(binary.BigEndian.Uint16(sibling[sibOffset:]))]
	// Block 0 of the contact credential signed by its holder, not the transport key.
	contactDecoded, err := agenttransport.DecodeCredential(contact)
	if err != nil {
		return err
	}
	contactBlocks, err := contactDecoded.Blocks()
	if err != nil {
		return err
	}
	contactDelegation, err := contactDecoded.DelegationBytes()
	if err != nil {
		return err
	}
	forged := contactBlocks[0]
	preimage, err := agenttransport.BlockSigningPreimage(contactDelegation, nil, forged)
	if err != nil {
		return err
	}
	copy(forged.Signature[:], ed25519.Sign(g.key("holder-contact"), preimage))
	wrongCredential, err := agenttransport.NewCredential(contactDelegation, []agenttransport.Block{forged})
	if err != nil {
		return err
	}
	wrongSigner, err := wrongCredential.Encode()
	if err != nil {
		return err
	}
	join := func(count byte, parts ...[]byte) []byte {
		out := append([]byte{}, maximal[:headerEnd]...)
		out[headerEnd-1] = count
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	decodeCases := []struct {
		name string
		wire []byte
	}{
		{"truncated", contact[:len(contact)-1]},
		{"trailing", append(append([]byte{}, contact...), 0)},
		{"oversize", append(append([]byte{}, maximal...), make([]byte, agenttransport.MaxCredentialSize+1-len(maximal))...)},
		{"wrong-domain", mutate(contact, func(b []byte) []byte { b[0] ^= 1; return b })},
		{"bad-delegation", mutate(contact, func(b []byte) []byte { b[32+146] = 0; return b })},
		{"zero-blocks", header(0)},
		{"five-blocks", join(5, blocks[0], blocks[1], blocks[2], blocks[3], blocks[3])},
		{"block-length-long", mutate(contact, func(b []byte) []byte { b[headerEnd+1]++; return b })},
		{"block-length-short", mutate(contact, func(b []byte) []byte { b[headerEnd+1]--; return b })},
		{"zero-caveats", withCaveats()},
		{"nine-caveats", append(header(1), rawBlockBytes(next, 9, okBlock0, sig)...)},
		{"caveat-count-exceeds-caveats", append(header(1), rawBlockBytes(next, 4, okBlock0, sig)...)},
		{"unknown-caveat-0", withCaveats(append([]rawCaveat{{0, nil}}, okBlock0...)...)},
		{"unknown-caveat-9", extra(rawCaveat{9, nil})},
		{"duplicate-caveat", withCaveats(okBlock0[0], okBlock0[0], okBlock0[1], okBlock0[2])},
		{"descending-caveats", withCaveats(okBlock0[1], okBlock0[0], okBlock0[2])},
		{"short-time-caveat", withCaveats(rawCaveat{1, u64(baseTime)[:7]}, okBlock0[1], okBlock0[2])},
		{"empty-relay", extra(rawCaveat{3, nil})},
		{"relay-trailing-slash", extra(rawCaveat{3, []byte(relayA + "/")})},
		{"relay-plain-http", extra(rawCaveat{3, []byte("http://relay-a.example")})},
		{"relay-uppercase-host", extra(rawCaveat{3, []byte("https://Relay-a.example")})},
		{"relay-query", extra(rawCaveat{3, []byte(relayA + "?x")})},
		{"relay-percent", extra(rawCaveat{3, []byte(relayA + "/a%20b")})},
		{"relay-257", extra(rawCaveat{3, []byte(maximalRelay("relay-max") + "q")})},
		{"operations-unknown-bit", withCaveats(okBlock0[0], okBlock0[1], rawCaveat{4, u16(0x20)})},
		{"operations-long", withCaveats(okBlock0[0], okBlock0[1], rawCaveat{4, u32(1)})},
		{"lane-zero", extra(rawCaveat{5, make([]byte, 16)})},
		{"lane-short", extra(rawCaveat{5, make([]byte, 15)})},
		{"max-envelopes-zero", extra(rawCaveat{6, u32(0)})},
		{"max-envelope-bytes-zero", extra(rawCaveat{7, u32(0)})},
		{"max-envelope-bytes-over", extra(rawCaveat{7, u32(agenttransport.MaxEnvelopeBytes + 1)})},
		{"max-lane-bytes-zero", extra(rawCaveat{8, u64(0)})},
		{"block0-no-operations", withCaveats(okBlock0[0], okBlock0[1])},
		{"block0-no-not-before", withCaveats(okBlock0[1], okBlock0[2])},
		{"block0-no-not-after", withCaveats(okBlock0[0], okBlock0[2])},
		{"block0-empty-window", withCaveats(okBlock0[0], rawCaveat{2, u64(baseTime)}, okBlock0[2])},
		{"block0-lifetime-over", withCaveats(okBlock0[0], rawCaveat{2, u64(baseTime + agenttransport.MaxCredentialSeconds + 1)}, okBlock0[2])},
		{"next-key-zero", append(header(1), rawBlockBytes(make([]byte, 32), 3, okBlock0, sig)...)},
		{"next-key-small-order", append(header(1), rawBlockBytes(small, 3, okBlock0, sig)...)},
		{"next-key-noncanonical", append(header(1), rawBlockBytes(noncanonical, 3, okBlock0, sig)...)},
	}
	for _, c := range decodeCases {
		if err := g.negative(c.name, "decode", c.wire); err != nil {
			return err
		}
	}
	delegations := g.delegations
	chainCases := []struct {
		name string
		wire []byte
	}{
		{"flipped-signature", mutate(contact, func(b []byte) []byte { b[len(b)-1] ^= 1; return b })},
		{"reordered-blocks", join(4, blocks[0], blocks[2], blocks[1], blocks[3])},
		{"dropped-middle-block", join(3, blocks[0], blocks[2], blocks[3])},
		{"spliced-block", join(2, blocks[0], sibBlock1)},
		{"other-delegation", mutate(contact, func(b []byte) []byte {
			copy(b[32:32+agenttransport.DelegationSize], delegations["contact-rotated"])
			return b
		})},
		{"zero-signature", withCaveats(okBlock0...)},
		{"signed-by-holder-key", wrongSigner},
	}
	for _, c := range chainCases {
		if err := g.negative(c.name, "chain", c.wire); err != nil {
			return err
		}
	}
	return nil
}

func runCredentials() error {
	g := &generator{out: credentialCorpus{Schema: credentialSchema}, keys: map[string]ed25519.PrivateKey{}, delegations: map[string][]byte{}, credentials: map[string][]byte{}}
	if err := g.build(); err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(g.out)
}
