package directory

import (
	"errors"
	"time"

	"github.com/tosnetwork/ai/messenger/pkg/e2ee"
	"github.com/tosnetwork/ai/messenger/pkg/eventlog"
	"github.com/tosnetwork/ai/messenger/pkg/fault"
	"github.com/tosnetwork/ai/messenger/pkg/relayframe"
)

// RelayFloorHorizon is how long a retired peer's floor must stay: the largest
// descriptor lifetime. Evidence is ordered by descriptor issue time, and
// evidence issued at or before a floor's time expires within this horizon of
// it, so once it has passed CheckPeer refuses all of it as expired and the
// floor holds nothing back.
const RelayFloorHorizon = MaxDescriptorLifetimeSeconds * time.Second

// SweepReport says what one sweep did.
type SweepReport struct {
	// Retired counts records whose expired evidence was retired to a floor.
	Retired int
	// Kept counts expired records left in place because the floor store had
	// no room past its horizon; keeping a record is always safe.
	Kept int
}

// SweepExpiredEvidence retires every committed record whose evidence can no
// longer pass CheckPeer because of its own expiry: its descriptor or one of
// its bundles has expired at now. Such evidence is refused by every route
// already, so the record only holds a slot of the store's peer bound. A
// record is never retired while its evidence is still usable by those
// times; one whose evidence does not decode is left for the caller to see.
// A record is retired to a floor (eventlog.RetireRelayEvidence), so the
// newer-only rule and the peer's admission stand. The daemon runs it at
// start and on its relay timer.
func (v RelayVerifier) SweepExpiredEvidence(now time.Time) (SweepReport, error) {
	if v.Store == nil {
		return SweepReport{}, fault.New(fault.CodeInternal, "relay evidence store is not configured")
	}
	if now.IsZero() || now.Unix() <= 0 {
		return SweepReport{}, errors.New("invalid relay evidence sweep time")
	}
	peers, err := v.Store.ListRelayEvidencePeers()
	if err != nil {
		return SweepReport{}, err
	}
	report := SweepReport{}
	for _, agentID := range peers {
		retired, kept, err := v.sweepPeer(agentID, now)
		if err != nil {
			return report, err
		}
		if retired {
			report.Retired++
		}
		if kept {
			report.Kept++
		}
	}
	return report, nil
}

// sweepPeer retires one peer's record if its evidence has expired. A commit
// for the peer runs under the same per-peer lock, so the record retired is
// the one read.
func (v RelayVerifier) sweepPeer(agentID string, now time.Time) (bool, bool, error) {
	unlock := lockPeer(agentID)
	defer unlock()
	evidence, found, err := v.Store.LoadRelayEvidence(agentID)
	if err != nil || !found {
		return false, false, err
	}
	until, digest, issued, err := evidenceUsableUntil(evidence)
	if err != nil {
		return false, false, err
	}
	if uint64(now.Unix()) < until {
		return false, false, nil
	}
	retired, err := v.Store.RetireRelayEvidence(agentID, relayframe.EvidenceDigest(evidence),
		eventlog.RelayEvidenceFloor{DescriptorDigest: digest, DescriptorIssuedAtUnix: issued}, RelayFloorHorizon, v.Contacts, now)
	if err != nil {
		return false, false, err
	}
	return retired, !retired, nil
}

// evidenceUsableUntil is the first time CheckPeer refuses evidence for its
// own expiry: the earliest of its descriptor's and its bundles' expiries. It
// also returns the evidence's ordering key, the descriptor digest and issue
// time. The evidence was verified when it was committed; this reads it only.
func evidenceUsableUntil(evidence []byte) (uint64, string, uint64, error) {
	decoded, err := relayframe.DecodeEvidence(evidence)
	if err != nil {
		return 0, "", 0, err
	}
	descriptor, err := DecodeDescriptorJSON(decoded.Descriptor)
	if err != nil {
		return 0, "", 0, err
	}
	digest, err := DescriptorDigest(descriptor)
	if err != nil {
		return 0, "", 0, err
	}
	bundles, err := e2ee.DecodeBundleSetJSON(decoded.BundleSet)
	if err != nil {
		return 0, "", 0, err
	}
	until := descriptor.ExpiresAtUnix
	for _, bundle := range bundles {
		if bundle.ExpiresAtUnix < until {
			until = bundle.ExpiresAtUnix
		}
	}
	if until == 0 || descriptor.IssuedAtUnix == 0 {
		return 0, "", 0, errors.New("stored relay evidence names no expiry")
	}
	return until, digest, descriptor.IssuedAtUnix, nil
}
