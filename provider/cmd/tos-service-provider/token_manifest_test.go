package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

func TestManifestSelectsThePinnedTokenRailExplicitly(t *testing.T) {
	dir := t.TempDir()
	code := "tvm-cell-sha256:" + hex.EncodeToString(nativecore.ServiceActorTokenTestProfileCodeHash[:])
	master := "0:" + strings.Repeat("ab", 32)
	pin := toschain.TokenAssetPin{Master: master, WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("cd", 32), MinterCodeHash: "tvm-cell-sha256:" + strings.Repeat("ef", 32), BridgeCodeHash: "tvm-cell-sha256:" + strings.Repeat("12", 32), Bridge: "-1:" + strings.Repeat("34", 32), BridgeConfigParam: 79, Decimals: 6, SourceChainID: 1}
	pin.SourceToken[19] = 1
	c := servicebridge.NodeConfig{AgentID: fixtureAgent, Token: &servicebridge.TokenProviderConfig{Pins: []toschain.TokenAssetPin{pin}, MonitorReport: filepath.Join(dir, "monitor.json"), Actors: []servicebridge.TokenActorConfig{{Address: fixtureActor, CodeHash: code, AssetID: "asset-a", Master: master, CapabilityID: fixtureCapability, Version: "1.0.0", ManifestFile: filepath.Join(dir, "manifest.cbor"), MinPriceAtomic: "1", MaxPriceAtomic: "100000000", MaxLiabilityAtomic: "100000000", MaxStorageFeeNanoTOS: "1000000000", MaxCleanupBountyNanoTOS: "1000000000", MinActorFreeNanoTOS: "100000000", MinWalletNanoTOS: "200000000"}}}}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"manifest", "--token-config", path, "--provider-agent", fixtureAgent, "--actor", fixtureActor, "--code-hash", code, "--attestor", fixtureAttestor, "--out-dir", dir}
	out, diag, status := invoke(t, args...)
	if status != 0 {
		t.Fatalf("%d %s %s", status, out, diag)
	}
	var result struct {
		Path string `json:"path"`
	}
	if err = json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if m.Settlement.Rail != nativecore.ServiceActorTokenRail || len(m.SupportedAssets) != 1 || hex.EncodeToString(m.SupportedAssets[0].MasterAccountID) != strings.TrimPrefix(master, "0:") {
		t.Fatalf("manifest %+v", m)
	}
	c.AgentID = "agent_" + strings.Repeat("bb", 32)
	raw, err = json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, status = invoke(t, args...); status == 0 {
		t.Fatal("another configured Agent accepted")
	}
}
