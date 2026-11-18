package toschain

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// tosctlWalletMessages are wallet external messages built and signed by
// tosctl, with the hash tosctl announces for each (see the file's source
// field).
type tosctlWalletMessages struct {
	Source   string `json:"source"`
	Messages []struct {
		Version    string `json:"version"`
		BOCBase64  string `json:"boc_base64"`
		Hash       string `json:"hash"`
		Seqno      uint32 `json:"seqno"`
		ValidUntil uint32 `json:"valid_until"`
	} `json:"messages"`
}

func loadTosctlWalletMessages(t *testing.T) tosctlWalletMessages {
	t.Helper()
	raw, err := os.ReadFile("testdata/tosctl-wallet-messages.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture tosctlWalletMessages
	if err := json.Unmarshal(raw, &fixture); err != nil || len(fixture.Messages) == 0 {
		t.Fatalf("fixture: %v", err)
	}
	return fixture
}

// externalWithBody builds an inbound external message to destination whose
// body is stored inline or in a reference: two valid encodings of one
// message, with different cell hashes.
func externalWithBody(t *testing.T, destination *address.Address, body *cell.Cell, inRef bool) *cell.Cell {
	t.Helper()
	builder := cell.BeginCell().MustStoreUInt(2, 2).MustStoreAddr(address.NewAddressNone()).MustStoreAddr(destination).
		MustStoreCoins(0).MustStoreBoolBit(false)
	if inRef {
		builder.MustStoreBoolBit(true).MustStoreRef(body)
	} else {
		builder.MustStoreBoolBit(false).MustStoreBuilder(body.ToBuilder())
	}
	return builder.EndCell()
}

// withStoredInbound returns the cell of transaction with its inbound
// message replaced by message, stored exactly as given, and the
// transaction parsed back from that cell.
func withStoredInbound(t *testing.T, transaction tlb.Transaction, message *cell.Cell) (tlb.Transaction, *cell.Cell) {
	t.Helper()
	root, err := transaction.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	io, err := root.PeekRef(0)
	if err != nil {
		t.Fatal(err)
	}
	ioSlice := io.MustBeginParse()
	if present, err := ioSlice.LoadBoolBit(); err != nil || !present {
		t.Fatal("the template transaction has no inbound message")
	}
	if _, err := ioSlice.LoadRefCell(); err != nil {
		t.Fatal(err)
	}
	newIO := cell.BeginCell().MustStoreBoolBit(true).MustStoreRef(message).MustStoreBuilder(ioSlice.ToBuilder()).EndCell()
	rootSlice := root.MustBeginParse()
	bits, err := rootSlice.LoadSlice(root.BitsSize())
	if err != nil {
		t.Fatal(err)
	}
	builder := cell.BeginCell().MustStoreSlice(bits, root.BitsSize()).MustStoreRef(newIO)
	for index := 1; index < int(root.RefsNum()); index++ {
		ref, err := root.PeekRef(index)
		if err != nil {
			t.Fatal(err)
		}
		builder.MustStoreRef(ref)
	}
	stored := builder.EndCell()
	var parsed tlb.Transaction
	if err := tlb.LoadFromCell(&parsed, stored.MustBeginParse()); err != nil {
		t.Fatal(err)
	}
	parsed.Hash = stored.Hash()
	return parsed, stored
}

// The external message hash is that of the inbound cell as the transaction
// stores it, which is the hash tosctl announces, whether the message stores
// its body inline (as tosctl does) or in a reference.
func TestTheExternalMessageHashIsTheStoredCellsAsTosctlAnnouncesIt(t *testing.T) {
	fixture := loadTosctlWalletMessages(t)
	template := buildTransaction(t, 11, 1001, nil, externalIn(t, cell.BeginCell().MustStoreUInt(1, 32).EndCell()), true, 0)
	differs := false
	for _, entry := range fixture.Messages {
		raw, err := base64.StdEncoding.DecodeString(entry.BOCBase64)
		if err != nil {
			t.Fatal(err)
		}
		tosctl, err := cell.FromBOC(raw)
		if err != nil {
			t.Fatal(err)
		}
		// The Go cell hash of tosctl's message is the hash tosctl announced.
		if hex.EncodeToString(tosctl.Hash()) != entry.Hash {
			t.Fatalf("%s: Go hashes tosctl's message as %x, tosctl announced %s", entry.Version, tosctl.Hash(), entry.Hash)
		}
		var message tlb.Message
		if err := tlb.LoadFromCell(&message, tosctl.MustBeginParse()); err != nil || message.MsgType != tlb.MsgTypeExternalIn {
			t.Fatalf("%s: tosctl's message does not parse as an inbound external message: %v", entry.Version, err)
		}
		external := message.AsExternalIn()
		inline := externalWithBody(t, external.DstAddr, external.Body, false)
		referenced := externalWithBody(t, external.DstAddr, external.Body, true)
		if !bytesEqual(inline.Hash(), tosctl.Hash()) {
			t.Fatalf("%s: tosctl does not store its body inline as this test assumes", entry.Version)
		}
		for name, stored := range map[string]*cell.Cell{"inline": inline, "in a reference": referenced} {
			transaction, root := withStoredInbound(t, template, stored)
			reduced, err := reduceWalletTransaction(transaction, root)
			if err != nil {
				t.Fatalf("%s, body %s: %v", entry.Version, name, err)
			}
			if reduced.ExternalMessageHash != hex.EncodeToString(stored.Hash()) {
				t.Errorf("%s, body %s: hashed %s, stored %x", entry.Version, name, reduced.ExternalMessageHash, stored.Hash())
			}
			reencoded, err := transaction.IO.In.ToCell()
			if err != nil {
				t.Fatal(err)
			}
			if !bytesEqual(reencoded.Hash(), stored.Hash()) {
				differs = true
			}
		}
	}
	// At least one stored form must differ from the re-encoded one, or this
	// test could not tell the stored cell from a re-encoding.
	if !differs {
		t.Fatal("no stored form differs from its re-encoding")
	}
}

func bytesEqual(a, b []byte) bool { return hex.EncodeToString(a) == hex.EncodeToString(b) }
