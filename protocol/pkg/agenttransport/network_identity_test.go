package agenttransport

import "testing"

func TestNetworkIdentityIsAValueNotMutableVerifierState(t *testing.T) {
	f := newFixture(t)
	v := f.verifier(t)
	original := v.NetworkIdentity()
	if original != ([3]string{f.c.Network.NetworkId, f.c.Network.GenesisRootHash, f.c.Network.GenesisFileHash}) {
		t.Fatal("wrong network tuple")
	}
	changed := v.NetworkIdentity()
	changed[1] = "other"
	if v.NetworkIdentity() != original {
		t.Fatal("caller changed the verifier network")
	}
	var empty *Verifier
	if empty.NetworkIdentity() != ([3]string{}) || (&Verifier{}).NetworkIdentity() != ([3]string{}) {
		t.Fatal("unconfigured verifier has an identity")
	}
}
