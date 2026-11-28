package agenttransport

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func TestAuthenticatedRevocationIsDistinctFromMalformedState(t *testing.T) {
	for _, kind := range []string{"absent", "tombstone", "delegation-removed", "policy-changed", "epoch-advanced", "epoch-missing", "epoch-checkpoint", "epoch-future", "admission-missing", "policy-missing", "wrong-account-tombstone"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			revoked := true
			switch kind {
			case "absent":
				f.r.snapshot.State = nil
			case "tombstone":
				f.r.snapshot.State.GetAgent().Tombstoned = true
			case "delegation-removed":
				f.r.snapshot.State.GetAgent().DelegationDigests = nil
			case "policy-changed":
				f.d.PolicyHash[0] ^= 1
			case "epoch-advanced":
				*f.r.snapshot.CurrentEpoch = 2
			case "epoch-missing":
				f.r.snapshot.CurrentEpoch = nil
				revoked = false
			case "epoch-checkpoint":
				f.r.snapshot.EpochCheckpoint = 9
				revoked = false
			case "epoch-future":
				f.d.AuthorizationEpoch = 2

				revoked = false
			case "admission-missing":
				f.r.snapshot.AdmissionEpochs = nil
				revoked = false
			case "policy-missing":
				f.r.snapshot.State.GetAgent().Policy = nil
				revoked = false
			case "wrong-account-tombstone":
				f.r.snapshot.State.Reference.Account = "0:other"
				f.r.snapshot.State.GetAgent().Tombstoned = true
				revoked = false
			}
			if kind == "epoch-future" || kind == "policy-changed" {
				raw, err := f.d.Encode()
				if err != nil {
					t.Fatal(err)
				}
				f.wire = raw
				hash := sha256.Sum256(raw)
				f.r.snapshot.State.GetAgent().DelegationDigests = []string{"sha256:" + hex.EncodeToString(hash[:])}
				f.r.snapshot.AdmissionEpochs = map[[32]byte]uint64{hash: f.d.AuthorizationEpoch}
			}
			v, err := NewVerifier(f.c, f.r)
			if err != nil {
				t.Fatal(err)
			}
			_, err = v.VerifyDelegation(t.Context(), f.wire, Relay)
			if err == nil || errors.Is(err, ErrDelegationRevoked) != revoked {
				t.Fatal(kind, "revoked=", revoked, err)
			}
		})
	}
}

func TestFinalizedPresenceCannotBeInconsistent(t *testing.T) {
	f := newFixture(t)
	adapter, err := NewLegacyTestNetworkResolver(TestNetworkLegacyEpochZero, f.c.Network, legacySource{found: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = adapter.ResolveFinalizedAgent(t.Context(), f.d.AgentID()); err == nil || errors.Is(err, ErrDelegationRevoked) {
		t.Fatal("inconsistent presence must be an integrity refusal", err)
	}
}
