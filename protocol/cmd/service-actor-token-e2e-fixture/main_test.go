package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

func fixtureInput(t *testing.T) input {
	t.Helper()
	raw, e := os.ReadFile("../../../spec/test-vectors/service-actor-token-conformance-vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Data string `json:"deploy_data_boc_base64"`
	}
	if e = json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	data, e := decodeCell(v.Data)
	if e != nil {
		t.Fatal(e)
	}
	d, e := nativecore.DecodeServiceActorTokenData(data)
	if e != nil {
		t.Fatal(e)
	}
	repo := os.Getenv("TOS_SERVICE_TOKEN_CLI_REPO")
	if repo == "" {
		t.Fatal("TOS_SERVICE_TOKEN_CLI_REPO must name the pinned contract checkout")
	}
	code, e := os.ReadFile(filepath.Join(repo, "crypto/smartcont/tos-service-actor-token-v1-test.boc.base64"))
	if e != nil {
		t.Fatal(e)
	}
	return input{Owner: d.Owner.Text(), Master: d.Route.Master.Text(), WalletCode: base64.StdEncoding.EncodeToString(d.Route.WalletCode.ToBOC()), ActorCode: strings.TrimSpace(string(code)), Price: "1000000", MaxLiability: "10000000", Metadata: strings.Repeat("11", 32)}
}
func TestDeploymentBindsOwnerRouteAndCode(t *testing.T) {
	p := fixtureInput(t)
	raw, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	if e = run(bytes.NewReader(raw), &out); e != nil {
		t.Fatal(e)
	}
	var result output
	if e = json.Unmarshal(out.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	data, e := decodeCell(result.Data)
	if e != nil {
		t.Fatal(e)
	}
	d, e := nativecore.DecodeServiceActorTokenData(data)
	if e != nil {
		t.Fatal(e)
	}
	if d.Owner.Text() != p.Owner || d.Route.Master.Text() != p.Master || d.Policy.ResponseSLA != 600 || d.Policy.PricePerCall.String() != p.Price {
		t.Fatal("deployment fields lost")
	}
	init, e := decodeCell(result.StateInit)
	if e != nil {
		t.Fatal(e)
	}
	if len(init.Hash()) != 32 || !strings.HasSuffix(result.Address, hex.EncodeToString(init.Hash())) {
		t.Fatal("state-init address not bound")
	}
	for name, change := range map[string]func(*input){"owner": func(p *input) { p.Owner = "-1:" + strings.Repeat("11", 32) }, "code": func(p *input) { p.ActorCode = p.WalletCode }, "master": func(p *input) { p.Master = "bad" }, "amount": func(p *input) { p.Price = "0" }, "metadata": func(p *input) { p.Metadata = "00" }} {
		t.Run(name, func(t *testing.T) {
			q := p
			change(&q)
			raw, _ := json.Marshal(q)
			if run(bytes.NewReader(raw), &bytes.Buffer{}) == nil {
				t.Fatal("invalid fixture accepted")
			}
		})
	}
}
func TestFundingKeepsEqualHashesAndRejectsTrailingInput(t *testing.T) {
	p := fixtureInput(t)
	text := strings.Repeat("22", 32)
	in := map[string]any{"actor": p.Owner, "response": p.Owner, "query_id": uint64(7), "amount_atomic": "1000000", "forward_nanotos": "100000000", "request_hash": text, "terms_hash": text}
	raw, e := json.Marshal(in)
	if e != nil {
		t.Fatal(e)
	}
	var out bytes.Buffer
	if e = funding(bytes.NewReader(raw), &out); e != nil {
		t.Fatal(e)
	}
	var value map[string]string
	if e = json.Unmarshal(out.Bytes(), &value); e != nil {
		t.Fatal(e)
	}
	body, e := decodeCell(value["body_boc"])
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := nativecore.DecodeServiceActorTokenFundingTransfer(body)
	if e != nil {
		t.Fatal(e)
	}
	if decoded.Payload.RequestHash != decoded.Payload.ExpectedTermsHash || decoded.Payload.RequestHash[0] != 0x22 {
		t.Fatal("equal request and terms hashes changed")
	}
	if funding(strings.NewReader(string(raw)+" {}"), &bytes.Buffer{}) == nil {
		t.Fatal("trailing input accepted")
	}
}
