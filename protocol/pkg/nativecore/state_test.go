package nativecore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func testLocator(t *testing.T) *Locator {
	t.Helper()
	code := cell.BeginCell().MustStoreUInt(0xdeadbeef, 32).EndCell()
	l, err := NewLocator(&nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)},
		0, base64.StdEncoding.EncodeToString(code.ToBOC()), "tvm-cell-sha256:"+hex.EncodeToString(code.Hash()))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLocatorAndAgentTypedStateRoundTrip(t *testing.T) {
	l := testLocator(t)
	policy, _ := testPolicy(t)
	policyCell, _ := PolicyCell(policy)
	nonce := []byte(strings.Repeat("o", 32))
	id, err := DeriveAgentID(l.Network, nonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := l.Locate(id)
	if err != nil || !strings.HasPrefix(identity.Address, "0:") {
		t.Fatalf("locate: %v", err)
	}
	delegations := cell.BeginCell().MustStoreUInt(0, 16).MustStoreUInt(0, 16).MustStoreDict(nil).EndCell()
	recovery := cell.BeginCell().MustStoreBoolBit(false).EndCell()
	state := cell.BeginCell().MustStoreUInt(stateMagic, 32).MustStoreUInt(2, 16).MustStoreUInt(1, 8).
		MustStoreBoolBit(false).MustStoreUInt(1, 64).MustStoreUInt(1, 64).MustStoreSlice(bytes32(0x33), 256).
		MustStoreUInt(1, 64).MustStoreRef(policyCell).MustStoreRef(delegations).MustStoreRef(recovery).EndCell()
	config, _ := l.configCell()
	rawID, _, _ := objectID(id)
	data := cell.BeginCell().MustStoreUInt(dataMagic, 32).MustStoreUInt(1, 16).MustStoreUInt(1, 8).
		MustStoreSlice(rawID, 256).MustStoreRef(config).MustStoreBoolBit(true).MustStoreRef(state).EndCell()
	decoded, found, err := l.DecodeData(data, id)
	if err != nil || !found || decoded.GetAgent().GetAgentId() != id || decoded.GetAgent().GetPolicy().GetControllers()[0].GetKeyId() != policy.Controllers[0].KeyId {
		t.Fatalf("decode Agent: found=%v err=%v state=%v", found, err, decoded)
	}
	anyState, anyFound, anyID, err := l.DecodeDataAny(data)
	if err != nil || !anyFound || anyID != id || anyState.GetAgent().GetAgentId() != id {
		t.Fatalf("decode address-selected Agent: id=%q found=%v err=%v", anyID, anyFound, err)
	}
	first, found, err := l.DecodePortable(data, id)
	if err != nil || !found {
		t.Fatal(err)
	}
	second, _, err := l.DecodePortable(data, id)
	if err != nil || string(first) != string(second) {
		t.Fatal("portable projection is not deterministic")
	}
}

func TestCapabilityTypedStatePreservesVersionName(t *testing.T) {
	l := testLocator(t)
	owner := "agent_" + strings.Repeat("44", 32)
	version := &nativev1.CapabilityVersionV1{Version: "1.2.3", ManifestDigest: "sha256:" + strings.Repeat("55", 32)}
	id, err := DeriveCapabilityID(l.Network, []byte(strings.Repeat("c", 32)), owner, version)
	if err != nil {
		t.Fatal(err)
	}
	versionKey := sha256.Sum256([]byte(version.Version))
	dict := cell.NewDict(256)
	key := cell.BeginCell().MustStoreSlice(versionKey[:], 256).EndCell()
	manifest, _ := digestBytes(version.ManifestDigest, "sha256:", false)
	value := cell.BeginCell().MustStoreSlice(manifest, 256).MustStoreBoolBit(false).MustStoreRef(stringCell(version.Version)).EndCell()
	if err := dict.Set(key, value); err != nil {
		t.Fatal(err)
	}
	versions := cell.BeginCell().MustStoreUInt(1, 16).MustStoreDict(dict).EndCell()
	ownerRaw, _, _ := objectID(owner)
	state := cell.BeginCell().MustStoreUInt(stateMagic, 32).MustStoreUInt(2, 16).MustStoreUInt(2, 8).
		MustStoreBoolBit(false).MustStoreUInt(1, 64).MustStoreUInt(1, 64).MustStoreSlice(bytes32(0x66), 256).
		MustStoreSlice(ownerRaw, 256).MustStoreRef(versions).EndCell()
	config, _ := l.configCell()
	rawID, _, _ := objectID(id)
	data := cell.BeginCell().MustStoreUInt(dataMagic, 32).MustStoreUInt(1, 16).MustStoreUInt(2, 8).
		MustStoreSlice(rawID, 256).MustStoreRef(config).MustStoreBoolBit(true).MustStoreRef(state).EndCell()
	decoded, found, err := l.DecodeData(data, id)
	if err != nil || !found || len(decoded.GetCapability().GetVersions()) != 1 || decoded.GetCapability().GetVersions()[0].GetVersion() != version.Version {
		t.Fatalf("decode Capability: found=%v err=%v state=%v", found, err, decoded)
	}
	anyState, anyFound, anyID, err := l.DecodeDataAny(data)
	if err != nil || !anyFound || anyID != id || anyState.GetCapability().GetCapabilityId() != id {
		t.Fatalf("decode address-selected Capability: id=%q found=%v err=%v", anyID, anyFound, err)
	}
}

func TestPendingRecoveryIsBoundToLivePolicy(t *testing.T) {
	l := testLocator(t)
	policy, _ := testPolicy(t)
	policyCell, _ := PolicyCell(policy)
	id, err := DeriveAgentID(l.Network, bytes32('o'), policy)
	if err != nil {
		t.Fatal(err)
	}
	buildData := func(policyHash []byte) *cell.Cell {
		delegations := cell.BeginCell().MustStoreUInt(0, 16).MustStoreUInt(0, 16).MustStoreDict(nil).EndCell()
		recovery := cell.BeginCell().MustStoreBoolBit(true).MustStoreSlice(bytes32('i'), 256).
			MustStoreSlice(policyHash, 256).MustStoreUInt(1234, 64).MustStoreRef(policyCell).EndCell()
		state := cell.BeginCell().MustStoreUInt(stateMagic, 32).MustStoreUInt(2, 16).MustStoreUInt(1, 8).
			MustStoreBoolBit(false).MustStoreUInt(1, 64).MustStoreUInt(2, 64).MustStoreSlice(bytes32('a'), 256).
			MustStoreUInt(1, 64).MustStoreRef(policyCell).MustStoreRef(delegations).MustStoreRef(recovery).EndCell()
		config, _ := l.configCell()
		rawID, _, _ := objectID(id)
		return cell.BeginCell().MustStoreUInt(dataMagic, 32).MustStoreUInt(1, 16).MustStoreUInt(1, 8).
			MustStoreSlice(rawID, 256).MustStoreRef(config).MustStoreBoolBit(true).MustStoreRef(state).EndCell()
	}
	decoded, found, err := l.DecodeData(buildData(policyCell.Hash()), id)
	if err != nil || !found || decoded.GetAgent().GetRecoveryInitiatingPolicyHash() != "tvm-cell-sha256:"+hex.EncodeToString(policyCell.Hash()) {
		t.Fatalf("valid bound recovery: found=%v err=%v state=%v", found, err, decoded)
	}
	if _, _, err := l.DecodeData(buildData(bytes32('x')), id); err == nil {
		t.Fatal("recovery bound to a stale policy hash was accepted")
	}
}

func bytes32(value byte) []byte { return []byte(strings.Repeat(string([]byte{value}), 32)) }

func TestV1TypedStatesAreRefused(t *testing.T) {
	for _, kind := range []uint8{1, 2} {
		legacy := cell.BeginCell().MustStoreUInt(stateMagic, 32).MustStoreUInt(1, 16).
			MustStoreUInt(uint64(kind), 8).EndCell()
		_, err := decodeState(legacy, "", kind)
		if err == nil || !strings.Contains(err.Error(), "expected schema 2") {
			t.Fatalf("legacy kind %d: %v", kind, err)
		}
	}
}

func TestDelegationStateStrictReader(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		size, live, total, admission uint64
		withdrawn                    bool
		key                          byte
		want                         string
	}{
		{"live", 65, 1, 1, 7, false, 1, ""},
		{"withdrawn", 65, 0, 1, 7, true, 1, ""},
		{"admission-epoch", 65, 1, 1, 8, false, 1, "epoch mismatch"},
		{"zero-digest", 65, 1, 1, 7, false, 0, "invalid Native delegation key"},
		{"live-count", 65, 0, 1, 7, false, 1, "live delegation count mismatch"},
		{"total-count", 65, 1, 2, 7, false, 1, "total delegation count mismatch"},
		{"live-bound", 65, 129, 129, 7, false, 1, "invalid Native live delegation count"},
		{"total-bound", 65, 1, 385, 7, false, 1, "invalid Native total delegation count"},
		{"short-leaf", 64, 1, 1, 7, false, 1, "leaf shape"},
		{"long-leaf", 66, 1, 1, 7, false, 1, "leaf shape"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := cell.BeginCell().MustStoreUInt(tc.admission, 64)
			if tc.size >= 65 {
				value.MustStoreBoolBit(tc.withdrawn)
			}
			if tc.size > 65 {
				value.MustStoreBoolBit(false)
			}
			dict := cell.NewDict(256)
			if err := dict.SetBuilderByBytesKey(bytes32(tc.key), value); err != nil {
				t.Fatal(err)
			}
			wrapper := cell.BeginCell().MustStoreUInt(tc.live, 16).MustStoreUInt(tc.total, 16).MustStoreDict(dict).EndCell()
			entries, err := decodeDelegations(wrapper, 7)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("wanted %q, got %v", tc.want, err)
				}
				return
			}
			if err != nil || len(entries) != 1 || entries[0].AdmissionEpoch != 7 || entries[0].Withdrawn != tc.withdrawn {
				t.Fatalf("entries: %v, error: %v", entries, err)
			}
		})
	}
}

func TestIdentityObjectKindTags(t *testing.T) {
	network := testLocator(t).Network
	policy, _ := testPolicy(t)
	domain, err := domainCell(network)
	if err != nil {
		t.Fatal(err)
	}
	policyCell, err := PolicyCell(policy)
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes32('n')
	agentPreimage := func(tag uint64) *cell.Cell {
		return cell.BeginCell().MustStoreUInt(identityMagic, 32).MustStoreUInt(tag, 8).
			MustStoreSlice(nonce, 256).MustStoreSlice(policyCell.Hash(), 256).MustStoreRef(domain).EndCell()
	}
	legacy, v2 := agentPreimage(1), agentPreimage(3)
	agent, err := DeriveAgentID(network, nonce, policy)
	if err != nil || agent != "agent_"+hex.EncodeToString(v2.Hash()) || agent == "agent_"+hex.EncodeToString(legacy.Hash()) {
		t.Fatalf("Agent identity does not bind tag 3 independently of legacy: %s, %v", agent, err)
	}
	version := &nativev1.CapabilityVersionV1{Version: "1.0", ManifestDigest: "sha256:" + strings.Repeat("22", 32)}
	versionHash, manifest, err := capabilityVersion(version)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := objectID(agent)
	if err != nil {
		t.Fatal(err)
	}
	capabilityPreimage := cell.BeginCell().MustStoreUInt(identityMagic, 32).MustStoreUInt(2, 8).
		MustStoreSlice(nonce, 256).MustStoreSlice(owner, 256).MustStoreRef(domain).
		MustStoreRef(cell.BeginCell().MustStoreSlice(versionHash, 256).MustStoreSlice(manifest, 256).EndCell()).EndCell()
	capability, err := DeriveCapabilityID(network, nonce, agent, version)
	if err != nil || capability != "cap_"+hex.EncodeToString(capabilityPreimage.Hash()) {
		t.Fatalf("Capability identity does not bind tag 2: %s, %v", capability, err)
	}
}
