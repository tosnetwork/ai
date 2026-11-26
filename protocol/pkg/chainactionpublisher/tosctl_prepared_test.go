package chainactionpublisher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/chain"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func TestBroadcastPreparedContractCellValidatesTOSStatus(t *testing.T) {
	for _, test := range []struct {
		name   string
		result map[string]any
		ok     bool
	}{
		{name: "accepted", result: map[string]any{"status": 1}, ok: true},
		{name: "rejected", result: map[string]any{"status": -1}},
		{name: "unknown response field", result: map[string]any{"status": 1, "unbound": true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				var call struct {
					JSONRPC string `json:"jsonrpc"`
					ID      uint64 `json:"id"`
					Method  string `json:"method"`
				}
				if err := json.NewDecoder(request.Body).Decode(&call); err != nil || call.JSONRPC != "2.0" || call.Method != "sendBoc" {
					t.Fatalf("unexpected JSON-RPC call: %+v err=%v", call, err)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": call.ID, "ok": true, "result": test.result})
			}))
			defer server.Close()
			client, err := chain.NewClient(server.URL, time.Second, 4096)
			if err != nil {
				t.Fatal(err)
			}
			backend := &TosctlBackend{client: client}
			boc := base64.StdEncoding.EncodeToString([]byte("signed-wallet-message"))
			err = backend.BroadcastPreparedContractCell(context.Background(), boc, sha256Text([]byte("signed-wallet-message")))
			if (err == nil) != test.ok {
				t.Fatalf("accepted=%v want=%v err=%v", err == nil, test.ok, err)
			}
		})
	}
}

func TestPreparedContractCellRequiresExactSemanticConfirmation(t *testing.T) {
	body := cell.BeginCell().MustStoreUInt(0x4e560001, 32).EndCell()
	stateInit := cell.BeginCell().MustStoreUInt(0x11, 8).EndCell()
	payer, err := address.ParseRawAddr("0:" + strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	signed := cell.BeginCell().MustStoreSlice(make([]byte, 64), 512).MustStoreInt(3, 32).MustStoreUInt(0, 32).MustStoreUInt(2000000120, 32).MustStoreUInt(7, 32).MustStoreUInt(0, 8).MustStoreUInt(3, 8).MustStoreRef(body).EndCell()
	message, err := tlb.ToCell(&tlb.ExternalMessage{DstAddr: payer, Body: signed})
	if err != nil {
		t.Fatal(err)
	}
	bodyHash := "tvm-cell-sha256:" + fmt.Sprintf("%x", body.Hash())
	stateInitHash := "tvm-cell-sha256:" + fmt.Sprintf("%x", stateInit.Hash())
	value := preparedContractCell{Version: PreparedContractCellVersion, ValidUntil: 2000000120,
		MessageBOCBase64: base64.StdEncoding.EncodeToString(message.ToBOC()), Wallet: "relay",
		Payer: "0:" + strings.Repeat("11", 32), Destination: "0:" + strings.Repeat("22", 32),
		AmountNanoTOS: 200_000_000, BodyHash: bodyHash, StateInitHash: stateInitHash}
	encode := func(t *testing.T, item preparedContractCell) []byte {
		t.Helper()
		raw, err := json.Marshal(item)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, _, err := validatePreparedContractCell(encode(t, value), value.Wallet, value.Payer,
		value.Destination, value.AmountNanoTOS, bodyHash, stateInitHash); err != nil {
		t.Fatal(err)
	}
	for _, shape := range []string{"missing", "unknown", "null", "overflow"} {
		var answer map[string]any
		if err := json.Unmarshal(encode(t, value), &answer); err != nil {
			t.Fatal(err)
		}
		switch shape {
		case "missing":
			delete(answer, "valid_until")
		case "unknown":
			answer["extra"] = true
		case "null":
			answer["valid_until"] = nil
		case "overflow":
			answer["valid_until"] = uint64(1) << 32
		}
		raw, err := json.Marshal(answer)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err = validatePreparedContractCell(raw, value.Wallet, value.Payer, value.Destination, value.AmountNanoTOS, bodyHash, stateInitHash); err == nil {
			t.Fatalf("accepted %s", shape)
		}
	}
	mutations := []func(*preparedContractCell){
		func(v *preparedContractCell) { v.Version = "tosctl.wallet-prepared-send.v1" },
		func(v *preparedContractCell) { v.ValidUntil = 0 },
		func(v *preparedContractCell) { v.ValidUntil++ },
		func(v *preparedContractCell) { v.Destination = "0:" + strings.Repeat("33", 32) },
		func(v *preparedContractCell) { v.AmountNanoTOS++ },
		func(v *preparedContractCell) { v.BodyHash = "tvm-cell-sha256:" + strings.Repeat("44", 32) },
		func(v *preparedContractCell) { v.StateInitHash = "" },
		func(v *preparedContractCell) { v.Wallet = "other" },
	}
	for i, mutate := range mutations {
		changed := value
		mutate(&changed)
		if _, _, err := validatePreparedContractCell(encode(t, changed), value.Wallet, value.Payer,
			value.Destination, value.AmountNanoTOS, bodyHash, stateInitHash); err == nil {
			t.Fatalf("semantic mutation %d was accepted", i)
		}
	}
}

func TestPreparedContractCellBindsEchoToSignedWalletExpiry(t *testing.T) {
	raw, err := os.ReadFile("../toschain/testdata/tosctl-wallet-messages.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Messages []struct {
			Version    string `json:"version"`
			BOC        string `json:"boc_base64"`
			ValidUntil uint32 `json:"valid_until"`
		} `json:"messages"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil || len(fixture.Messages) != 2 {
		t.Fatalf("wallet fixtures: %v", err)
	}
	for _, entry := range fixture.Messages {
		t.Run(entry.Version, func(t *testing.T) {
			bytes, e := base64.StdEncoding.DecodeString(entry.BOC)
			if e != nil {
				t.Fatal(e)
			}
			root, e := cell.FromBOC(bytes)
			if e != nil {
				t.Fatal(e)
			}
			slice, e := root.BeginParse()
			if e != nil {
				t.Fatal(e)
			}
			var message tlb.ExternalMessage
			if e = tlb.LoadFromCell(&message, slice); e != nil {
				t.Fatal(e)
			}
			value := preparedContractCell{Version: PreparedContractCellVersion, ValidUntil: entry.ValidUntil, MessageBOCBase64: entry.BOC, Wallet: "publisher", Payer: message.DstAddr.StringRaw(), Destination: "0:" + strings.Repeat("77", 32), AmountNanoTOS: 200000000}
			answer, e := json.Marshal(value)
			if e != nil {
				t.Fatal(e)
			}
			if _, _, e = validatePreparedContractCell(answer, value.Wallet, value.Payer, value.Destination, value.AmountNanoTOS, value.BodyHash, value.StateInitHash); e != nil {
				t.Fatalf("signed fixture refused: %v", e)
			}
			value.ValidUntil++
			answer, e = json.Marshal(value)
			if e != nil {
				t.Fatal(e)
			}
			if _, _, e = validatePreparedContractCell(answer, value.Wallet, value.Payer, value.Destination, value.AmountNanoTOS, value.BodyHash, value.StateInitHash); e == nil || !strings.Contains(e.Error(), "expiry differs") {
				t.Fatalf("mismatched echo: %v", e)
			}
		})
	}
}

func TestPreparedWalletExpirySupportsV3AndRefusesUnsupportedMessages(t *testing.T) {
	payer := "0:" + strings.Repeat("11", 32)
	destination, err := address.ParseRawAddr(payer)
	if err != nil {
		t.Fatal(err)
	}
	// A V3 signature can begin with the V5 prefix. Body shape, not those
	// arbitrary signature bits, identifies where its expiry lives.
	signed := cell.BeginCell().MustStoreUInt(0x7369676e, 32).MustStoreSlice(make([]byte, 60), 480).MustStoreInt(3, 32).MustStoreUInt(0, 32).MustStoreUInt(2000000120, 32).MustStoreUInt(7, 32).MustStoreUInt(3, 8).MustStoreRef(cell.BeginCell().EndCell()).EndCell()
	external := func(body *cell.Cell) []byte {
		t.Helper()
		root, e := tlb.ToCell(&tlb.ExternalMessage{DstAddr: destination, Body: body})
		if e != nil {
			t.Fatal(e)
		}
		return root.ToBOC()
	}
	if expiry, e := preparedWalletExpiry(external(signed), payer); e != nil || expiry != 2000000120 {
		t.Fatalf("V3 expiry: %d %v", expiry, e)
	}
	v1 := cell.BeginCell().MustStoreSlice(make([]byte, 64), 512).MustStoreUInt(7, 32).MustStoreUInt(3, 8).MustStoreRef(cell.BeginCell().EndCell()).EndCell()
	for name, raw := range map[string][]byte{"malformed": {1, 2, 3}, "not external": cell.BeginCell().MustStoreUInt(0, 8).EndCell().ToBOC(), "no expiry": external(v1), "no body": external(nil)} {
		if _, e := preparedWalletExpiry(raw, payer); e == nil {
			t.Fatalf("accepted %s", name)
		}
	}
	if _, e := preparedWalletExpiry(external(signed), "0:"+strings.Repeat("22", 32)); e == nil {
		t.Fatal("another payer accepted")
	}
}
