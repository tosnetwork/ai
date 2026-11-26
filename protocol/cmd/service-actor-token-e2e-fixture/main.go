// Command service-actor-token-e2e-fixture builds unsigned, local-only actor
// deployment fixtures through the production token SDK. It holds no keys.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type input struct {
	Owner        string `json:"owner"`
	Master       string `json:"master"`
	WalletCode   string `json:"wallet_code_boc"`
	ActorCode    string `json:"actor_code_boc"`
	Price        string `json:"price_atomic"`
	MaxLiability string `json:"max_liability_atomic"`
	Metadata     string `json:"metadata_hash"`
}

type output struct {
	Address   string `json:"address"`
	StateInit string `json:"state_init_boc"`
	Data      string `json:"data_boc"`
	CodeHash  string `json:"code_hash"`
	Wallet    string `json:"wallet"`
}

func main() {
	action := run
	if len(os.Args) == 2 && os.Args[1] == "funding" {
		action = funding
	} else if len(os.Args) == 2 && os.Args[1] == "transaction" {
		action = transaction
	} else if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: service-actor-token-e2e-fixture [funding|transaction]")
		os.Exit(1)
	}
	if err := action(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func decodeCell(text string) (*cell.Cell, error) {
	b, e := base64.StdEncoding.DecodeString(text)
	if e != nil {
		return nil, e
	}
	return cell.FromBOC(b)
}
func run(in io.Reader, out io.Writer) error {
	d := json.NewDecoder(io.LimitReader(in, 1<<20))
	d.DisallowUnknownFields()
	var p input
	if e := d.Decode(&p); e != nil {
		return e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return errors.New("one JSON input required")
	}
	owner, e := nativecore.StandardAddress(p.Owner)
	if e != nil || owner.Workchain != 0 {
		return errors.New("owner must be basechain")
	}
	master, e := nativecore.StandardAddress(p.Master)
	if e != nil {
		return e
	}
	wallet, e := decodeCell(p.WalletCode)
	if e != nil {
		return e
	}
	code, e := decodeCell(p.ActorCode)
	if e != nil {
		return e
	}
	h := hex.EncodeToString(code.Hash())
	if h != hex.EncodeToString(nativecore.ServiceActorTokenTestProfileCodeHash[:]) {
		return errors.New("only the pinned local test actor is allowed")
	}
	price, ok := new(big.Int).SetString(p.Price, 10)
	if !ok || price.Sign() <= 0 || price.BitLen() > 119 {
		return errors.New("price outside bounds")
	}
	cap, ok := new(big.Int).SetString(p.MaxLiability, 10)
	if !ok || cap.Cmp(price) < 0 || cap.BitLen() > 119 {
		return errors.New("liability cap outside bounds")
	}
	metadata, e := hex.DecodeString(p.Metadata)
	if e != nil || len(metadata) != 32 {
		return errors.New("metadata must be 32 bytes")
	}
	policy := nativecore.ServiceActorTokenPolicyV1{ServiceActorPolicyV1: nativecore.ServiceActorPolicyV1{
		PricePerCall: price, StorageFee: big.NewInt(200000000), CleanupBounty: big.NewInt(100000000), ResponseSLA: 600, RefundClaimWindow: 600, OpenAccess: true, RateLimitPerDay: 100,
		ProofSchemeHash: nativecore.ServiceActorSoftwareWorkProofScheme}, MaxTokenLiability: cap}
	copy(policy.MetadataHash[:], metadata)
	route := nativecore.ServiceActorTokenAssetRouteV1{Master: master, WalletCode: wallet, BridgeConfigParam: 79}
	copy(route.WalletCodeHash[:], wallet.Hash())
	data, e := nativecore.BuildServiceActorTokenInitialData(p.Owner, policy, route)
	if e != nil {
		return e
	}
	// StateInit: absent split/special, code and data present, no library.
	init := cell.BeginCell().MustStoreUInt(0, 2).MustStoreBoolBit(true).MustStoreRef(code).MustStoreBoolBit(true).MustStoreRef(data).MustStoreBoolBit(false).EndCell()
	address := "0:" + hex.EncodeToString(init.Hash())
	ownWallet, e := nativecore.DeriveServiceActorTokenWallet(address, route)
	if e != nil {
		return e
	}
	result := output{address, base64.StdEncoding.EncodeToString(init.ToBOC()), base64.StdEncoding.EncodeToString(data.ToBOC()), h, ownWallet}
	return json.NewEncoder(out).Encode(result)
}

// funding intentionally does not apply admission prechecks: the local runner
// needs genuine underfunded and stale-terms messages to test on-chain refusal.
func funding(in io.Reader, out io.Writer) error {
	var p struct {
		QueryID  uint64 `json:"query_id"`
		Amount   string `json:"amount_atomic"`
		Forward  string `json:"forward_nanotos"`
		Actor    string `json:"actor"`
		Response string `json:"response"`
		Request  string `json:"request_hash"`
		Terms    string `json:"terms_hash"`
	}
	d := json.NewDecoder(io.LimitReader(in, 1<<16))
	d.DisallowUnknownFields()
	if e := d.Decode(&p); e != nil {
		return e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return errors.New("one JSON input required")
	}
	amount, ok := new(big.Int).SetString(p.Amount, 10)
	if !ok || amount.Sign() <= 0 || amount.BitLen() > 119 {
		return errors.New("invalid amount")
	}
	forward, ok := new(big.Int).SetString(p.Forward, 10)
	if !ok || forward.Sign() <= 0 || forward.BitLen() > 119 {
		return errors.New("invalid forward")
	}
	var request, terms [32]byte
	for i, text := range []string{p.Request, p.Terms} {
		target := []*[32]byte{&request, &terms}[i]
		raw, e := hex.DecodeString(text)
		if e != nil || len(raw) != 32 {
			return errors.New("hash must have 32 bytes")
		}
		copy(target[:], raw)
	}
	body, e := nativecore.BuildServiceActorTokenFundingTransfer(p.QueryID, amount, p.Actor, p.Response, forward, request, terms)
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(map[string]string{"body_boc": base64.StdEncoding.EncodeToString(body.ToBOC()), "body_hash": hex.EncodeToString(body.Hash())})
}

// transaction exposes the finalized-reader decoder for independently fetched
// public receipt cells. The caller must still anchor the cell to its checkpoint.
func transaction(in io.Reader, out io.Writer) error {
	var p struct {
		Actor string `json:"actor"`
		LT    uint64 `json:"lt"`
		Hash  string `json:"hash"`
		BOC   string `json:"boc"`
	}
	d := json.NewDecoder(io.LimitReader(in, 1<<20))
	d.DisallowUnknownFields()
	if e := d.Decode(&p); e != nil {
		return e
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return errors.New("one JSON input required")
	}
	raw, e := base64.StdEncoding.DecodeString(p.BOC)
	if e != nil {
		return e
	}
	tx, e := toschain.DecodeTokenActorTransaction(p.Actor, raw)
	if e != nil {
		return e
	}
	if p.LT == 0 || tx.LT != p.LT || len(p.Hash) != 64 || tx.Hash != p.Hash {
		return errors.New("transaction differs from its named account, lt or hash")
	}
	return json.NewEncoder(out).Encode(tx)
}
