package agentcarrier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/agentpacketrelay"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
)

type policyWriter interface {
	PublishPolicy(context.Context, string, agentpacketrelay.MailboxPolicy, []byte, ed25519.PrivateKey) error
}

var _ policyWriter = (*agentpacketrelay.V2Client)(nil)

// PublicationConfig is owner configuration. Peer cards cannot populate it.
type PublicationConfig struct {
	VerifyEvidence   agenttransport.ObjectVerifier
	Directories      []string
	Directory        func(string) (Directory, error)
	TestSingleRelay  bool
	PublishRailCard  bool
	PublicContact    bool
	Evidence         []byte
	TTL              time.Duration
	Policy           agentpacketrelay.MailboxPolicy
	PolicyConfigured bool
}
type publication struct {
	Raw         []byte                         `json:"raw"`
	Fingerprint [32]byte                       `json:"fingerprint"`
	Policy      agentpacketrelay.MailboxPolicy `json:"policy"`
	Hints       []string                       `json:"hints"`
	Policies    []string                       `json:"policies"`
}
type Publisher struct {
	lane        *Lane
	credentials *CredentialManager
	config      PublicationConfig
	store       *routingStore
	gate        gate
}
type PublicationView struct {
	HintTargets, PolicyTargets int
	Code                       string
}

func OpenPublisher(l *Lane, m *CredentialManager, c PublicationConfig) (*Publisher, error) {
	if l == nil || m == nil || m.store.identity != l.identity() || !bytes.Equal(m.config.Delegation, l.config.Delegation) || c.Directory == nil || !validRelays(c.Directories) || len(c.Directories) < 2 || (!c.TestSingleRelay && len(l.config.Relays) < 2) {
		return nil, ErrConfig
	}
	if !c.PolicyConfigured {
		c.Policy = agentpacketrelay.MailboxPolicy{StrangerCount: 32, StrangerBytes: 2 << 20}
	}
	if c.TTL == 0 {
		c.TTL = 6 * time.Hour
	}
	if c.TTL < time.Second || c.TTL > 24*time.Hour || c.TTL%time.Second != 0 || c.Policy.StrangerCount > 64 || c.Policy.StrangerBytes > 4<<20 {
		return nil, ErrConfig
	}
	if c.PublicContact && (c.VerifyEvidence == nil || len(c.Evidence) == 0) {
		return nil, ErrConfig
	}
	if c.PublishRailCard && l.config.Kind != Rail || (c.PublicContact && l.config.Kind != Chat) || (len(c.Evidence) > 0 && (!c.PublicContact || l.config.Kind != Chat)) {
		return nil, ErrConfig
	}
	c.Directories = append([]string(nil), c.Directories...)
	c.Evidence = bytes.Clone(c.Evidence)
	store, e := openRoutingStore(filepath.Join(l.config.StateDir, "publication-"+string(l.config.Kind)), l.identity())
	if e != nil {
		return nil, e
	}
	return &Publisher{l, m, c, store, make(gate, 1)}, nil
}
func (p *Publisher) Close() error { return p.store.Close() }
func (p *Publisher) Publish(ctx context.Context) (PublicationView, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*CallTimeout)
	defer cancel()
	if e := p.gate.lock(ctx); e != nil {
		return PublicationView{}, e
	}
	defer p.gate.unlock()
	d, fresh, e := p.credentials.authority(ctx)
	if e != nil {
		return PublicationView{Code: "transport-revoked"}, e
	}
	card, e := p.lane.CurrentCard(ctx)
	if e != nil {
		return PublicationView{}, e
	}
	objects := []agenttransport.HintObject{}
	if p.config.PublicContact {
		agent, err := p.config.VerifyEvidence(ctx, agenttransport.MessengerEvidence, bytes.Clone(p.config.Evidence))
		if err != nil || agent != p.lane.config.AgentID {
			return PublicationView{}, ErrRefused
		}
	}
	if p.config.PublishRailCard {
		objects = append(objects, agenttransport.HintObject{Kind: agenttransport.RailCard, Bytes: card.Packet})
	}
	if p.config.PublicContact {
		objects = append(objects, agenttransport.HintObject{Kind: agenttransport.ChatCard, Bytes: card.Packet})
		if len(p.config.Evidence) > 0 {
			objects = append(objects, agenttransport.HintObject{Kind: agenttransport.MessengerEvidence, Bytes: p.config.Evidence})
		}
	}
	// Fingerprint local configuration and exact public objects, not secret data.
	fingerprintBytes, e := encodePublicationConfig(p.lane.config.Relays, objects, p.config)
	if e != nil {
		return PublicationView{}, e
	}
	fingerprint := sha256.Sum256(append(fingerprintBytes, p.lane.config.Delegation...))
	var previous publication
	e = p.store.read(routingName("current"), &previous)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return PublicationView{}, e
	}
	exists := e == nil
	now, e := p.lane.now()
	if e != nil {
		return PublicationView{}, e
	}
	reuse := false
	if exists && (len(previous.Raw) == 0 || previous.Hints == nil || previous.Policies == nil) {
		return PublicationView{}, ErrStorage
	}
	if exists && len(previous.Raw) > 0 {
		h, decodeErr := agenttransport.DecodeHintRecord(previous.Raw)
		if decodeErr != nil || h.Hint.Delegation.AgentID() != p.lane.config.AgentID || (h.Hint.IssuedAt > now && h.Hint.IssuedAt-now > 300) || (previous.Policy.IssuedAt > now && previous.Policy.IssuedAt-now > 300) {
			return PublicationView{}, ErrStorage
		}
		reuse = previous.Fingerprint == fingerprint && now < h.Hint.IssuedAt+(h.Hint.ExpiresAt-h.Hint.IssuedAt)/2
	}
	current := previous
	if !reuse {
		if len(previous.Raw) > 0 {
			old, e := agenttransport.DecodeHintRecord(previous.Raw)
			if e != nil {
				return PublicationView{}, ErrStorage
			}
			if old.Hint.ExpiresAt+86400+300 > now {
				if e = p.lane.TrackRelays(ctx, old.Hint.Relays, old.Hint.ExpiresAt+86400+300); e != nil {
					return PublicationView{}, e
				}
			}
		}
		issued := now
		policyIssued := now
		if exists {
			old, e := agenttransport.DecodeHintRecord(previous.Raw)
			if e != nil {
				return PublicationView{}, ErrStorage
			}
			oldAuthority, e := old.Hint.Delegation.Encode()
			if e != nil {
				return PublicationView{}, ErrStorage
			}
			if bytes.Equal(oldAuthority, p.lane.config.Delegation) && old.Hint.IssuedAt >= issued {
				issued = old.Hint.IssuedAt + 1
			}
			if previous.Policy.IssuedAt >= policyIssued {
				policyIssued = previous.Policy.IssuedAt + 1
			}
		}
		if issued-now > 300 || policyIssued-now > 300 {
			return PublicationView{}, ErrUnavailable
		}
		expires := min(issued+uint64(p.config.TTL/time.Second), d.NotAfter)
		if expires <= issued {
			return PublicationView{}, ErrTransportRevoked
		}
		raw, e := p.lane.config.Verifier.BuildHintRecord(ctx, agenttransport.Hint{Delegation: d, IssuedAt: issued, ExpiresAt: expires, Relays: append([]string(nil), p.lane.config.Relays...)}, objects, p.credentials.key, agenttransport.PublishOptions{PublicContact: p.config.PublicContact, HintPolicy: p.lane.config.HintPolicy})
		if e != nil {
			return PublicationView{}, ErrRefused
		}
		if !p.lane.config.Now().Before(fresh) {
			return PublicationView{}, ErrTransportRevoked
		}
		current = publication{Raw: raw, Fingerprint: fingerprint, Policy: p.config.Policy, Hints: []string{}, Policies: []string{}}
		current.Policy.IssuedAt = policyIssued
		if e = p.lane.TrackRelays(ctx, p.lane.config.Relays, expires+86400+300); e != nil {
			return PublicationView{}, e
		}
		if e = p.store.write(routingName("current"), current); e != nil {
			return PublicationView{}, e
		}
	}
	targets := append([]string(nil), p.lane.config.Relays...)
	for _, url := range p.config.Directories {
		if !slices.Contains(targets, url) {
			targets = append(targets, url)
		}
	}
	for _, url := range targets {
		if ctx.Err() != nil {
			break
		}
		if !slices.Contains(current.Hints, url) {
			verified, err := p.lane.config.Verifier.VerifyHint(ctx, current.Raw, p.lane.config.HintPolicy)
			if err != nil {
				return PublicationView{}, ErrUnavailable
			}
			pass := resolvedRoute{FreshUntil: verified.FreshUntil, DelegationUntil: verified.Record.Hint.Delegation.NotAfter, HintUntil: verified.Record.Hint.ExpiresAt}
			client, err := p.config.Directory(url)
			if err == nil {
				if e = pass.validAt(p.lane.config.Now()); e != nil {
					return PublicationView{}, e
				}
				if ctx.Err() != nil {
					return PublicationView{}, ErrUnavailable
				}
				err = client.PublishHint(ctx, bytes.Clone(current.Raw))
			}
			if err == nil {
				current.Hints = append(current.Hints, url)
				if e = p.store.write(routingName("current"), current); e != nil {
					return PublicationView{}, e
				}
			}
		}
		if slices.Contains(p.lane.config.Relays, url) && !slices.Contains(current.Policies, url) {
			auth, pass, err := p.credentials.ownerAuthorization(ctx, url)
			if err != nil {
				return PublicationView{}, err
			}
			client, err := p.lane.config.Relay(url)
			if err == nil {
				if writer, ok := client.(policyWriter); ok {
					now, e := p.lane.now()
					if e != nil {
						return PublicationView{}, e
					}
					if e = checkCredential(auth, p.lane.config.AgentID, url, agenttransport.OperationPublish, now, nil); e != nil {
						return PublicationView{}, e
					}
					if ctx.Err() != nil {
						return PublicationView{}, ErrUnavailable
					}
					if e = pass.check(p.lane.config.Now()); e != nil {
						return PublicationView{}, e
					}
					err = writer.PublishPolicy(ctx, p.lane.config.AgentID, current.Policy, auth.wire, auth.holder)
				} else {
					err = ErrConfig
				}
			}
			if err == nil {
				current.Policies = append(current.Policies, url)
				if e = p.store.write(routingName("current"), current); e != nil {
					return PublicationView{}, e
				}
			}
		}
	}
	view := PublicationView{HintTargets: len(current.Hints), PolicyTargets: len(current.Policies)}
	if len(current.Hints) != len(targets) || len(current.Policies) != len(p.lane.config.Relays) {
		view.Code = "carrier-unavailable"
		return view, ErrUnavailable
	}
	return view, nil
}

func encodePublicationConfig(relays []string, objects []agenttransport.HintObject, c PublicationConfig) ([]byte, error) {
	raw, e := json.Marshal(struct {
		Relays, Directories []string
		Objects             []agenttransport.HintObject
		TTL                 int64
		Policy              agentpacketrelay.MailboxPolicy
	}{relays, c.Directories, objects, int64(c.TTL), c.Policy})
	if e != nil {
		return nil, ErrConfig
	}
	return raw, nil
}
