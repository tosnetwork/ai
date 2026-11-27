package main

import (
	"strings"
	"testing"
)

func tokenConfigFixture() tokenAssetConfig {
	h := "tvm-cell-sha256:" + strings.Repeat("ab", 32)
	return tokenAssetConfig{Master: "0:" + strings.Repeat("11", 32), Bridge: "-1:" + strings.Repeat("22", 32), BridgeConfigParam: 79, Decimals: 6, SourceChainID: 1, SourceToken: strings.Repeat("33", 20), BridgeCodeHash: h, MinterCodeHash: h, WalletCodeHash: h, MaxPerCallAtomic: "1000000", MaxWindowAtomic: "2000000"}
}
func TestTokenPolicyPinsEachAssetAndNeverCombinesCaps(t *testing.T) {
	a, b := tokenConfigFixture(), tokenConfigFixture()
	b.Master = "0:" + strings.Repeat("44", 32)
	b.MaxPerCallAtomic = "500"
	b.MaxWindowAtomic = "1000"
	pins, limits, err := tokenPolicy([]tokenAssetConfig{a, b})
	if err != nil || len(pins) != 2 || len(limits) != 2 {
		t.Fatalf("policy: %v %v", pins, err)
	}
	for _, c := range []tokenAssetConfig{a, b} {
		found := false
		for _, l := range limits {
			if l.MaxPerCallAtomic.String() == c.MaxPerCallAtomic && l.MaxWindowAtomic.String() == c.MaxWindowAtomic {
				found = true
			}
		}
		if !found {
			t.Fatal("asset caps changed")
		}
	}
}
func TestTokenPolicyRefusesMalformedAndDuplicateOwnerPolicy(t *testing.T) {
	edits := []func(*tokenAssetConfig){func(c *tokenAssetConfig) { c.Master = "bad" }, func(c *tokenAssetConfig) { c.Bridge = "0:" + strings.Repeat("22", 32) }, func(c *tokenAssetConfig) { c.SourceToken = strings.Repeat("AB", 20) }, func(c *tokenAssetConfig) { c.BridgeConfigParam = 84 }, func(c *tokenAssetConfig) { c.WalletCodeHash = "bad" }, func(c *tokenAssetConfig) { c.MaxPerCallAtomic = "01" }, func(c *tokenAssetConfig) { c.MaxWindowAtomic = "1" }, func(c *tokenAssetConfig) { c.MaxWindowAtomic = "1329227995784915872903807060280344576" }}
	for i, edit := range edits {
		c := tokenConfigFixture()
		edit(&c)
		if _, _, err := tokenPolicy([]tokenAssetConfig{c}); err == nil {
			t.Fatalf("accepted edit %d", i)
		}
	}
	c := tokenConfigFixture()
	if _, _, err := tokenPolicy([]tokenAssetConfig{c, c}); err == nil {
		t.Fatal("duplicate accepted")
	}
}

func TestClientPolicyHasTheSameTwoAssetBoundAsTheResolver(t *testing.T) {
	configs := make([]tokenAssetConfig, 3)
	for i := range configs {
		configs[i] = tokenConfigFixture()
		configs[i].Master = "0:" + strings.Repeat([]string{"11", "22", "33"}[i], 32)
	}
	if _, _, err := tokenPolicy(configs[:2]); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tokenPolicy(configs); err == nil || !strings.Contains(err.Error(), "at most two") {
		t.Fatalf("client accepted a policy its resolver refuses: %v", err)
	}
}

func TestTokenPolicyRequiresExplicitAssetPins(t *testing.T) {
	pins, limits, err := tokenPolicy(nil)
	if err != nil || len(pins) != 0 || len(limits) != 0 {
		t.Fatalf("implicit asset pins appeared: %v %v %v", pins, limits, err)
	}
}
