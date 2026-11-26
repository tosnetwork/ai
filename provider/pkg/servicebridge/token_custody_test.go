package servicebridge

import (
	"math/big"
	"strings"
	"testing"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func tokenWalletFixture(t *testing.T, kind string, seq uint32, global int64, mode uint64, extra bool) (*cell.Cell, string, string) {
	t.Helper()
	wallet := "0:" + strings.Repeat("11", 32)
	dest := "0:" + strings.Repeat("22", 32)
	payer, e := address.ParseRawAddr(wallet)
	if e != nil {
		t.Fatal(e)
	}
	to, e := address.ParseRawAddr(dest)
	if e != nil {
		t.Fatal(e)
	}
	body := cell.BeginCell().MustStoreUInt(0x53544306, 32).MustStoreUInt(5, 64).EndCell()
	amount, e := tlb.FromNano(big.NewInt(200000000), 9)
	if e != nil {
		t.Fatal(e)
	}
	msg, e := tlb.ToCell(&tlb.InternalMessage{IHRDisabled: true, Bounce: true, DstAddr: to, Amount: amount, Body: body})
	if e != nil {
		t.Fatal(e)
	}
	b := cell.BeginCell()
	if kind == "V5R1" {
		b.MustStoreUInt(0x7369676e, 32)
	} else {
		b.MustStoreSlice(make([]byte, 64), 512)
	}
	b.MustStoreInt(global, 32).MustStoreUInt(0, 32).MustStoreUInt(1800000120, 32).MustStoreUInt(uint64(seq), 32)
	if kind == "V4R2" {
		b.MustStoreUInt(0, 8)
	}
	if kind == "V5R1" {
		list, e := tlb.ToCell(&tlb.OutList{Prev: cell.BeginCell().EndCell(), Out: tlb.ActionSendMsg{Mode: uint8(mode), Msg: msg}})
		if e != nil {
			t.Fatal(e)
		}
		b.MustStoreBoolBit(true).MustStoreRef(list).MustStoreBoolBit(false).MustStoreSlice(make([]byte, 64), 512)
	} else {
		b.MustStoreUInt(mode, 8).MustStoreRef(msg)
	}
	if extra {
		b.MustStoreRef(msg)
	}
	root, e := tlb.ToCell(&tlb.ExternalMessage{DstAddr: payer, Body: b.EndCell()})
	if e != nil {
		t.Fatal(e)
	}
	return root, wallet, dest
}
func TestTokenCustodyValidatesEveryWalletEnvelope(t *testing.T) {
	for _, kind := range []string{"V3R2", "V4R2", "V5R1"} {
		t.Run(kind, func(t *testing.T) {
			root, wallet, dest := tokenWalletFixture(t, kind, 5, 3, 3, false)
			body := cell.BeginCell().MustStoreUInt(0x53544306, 32).MustStoreUInt(5, 64).EndCell()
			hash := takeTokenBodyHash(body.Hash())
			if expiry, e := checkTokenWalletMessage(root, kind, 3, 5, wallet, dest, 200000000, hash); e != nil || expiry != 1800000120 {
				t.Fatalf("%s %d %v", kind, expiry, e)
			}
			for _, bad := range []string{"seqno", "global", "mode", "extra", "amount", "body", "destination", "payer"} {
				t.Run(bad, func(t *testing.T) {
					seq, global, mode := uint32(5), int64(3), uint64(3)
					extra := false
					value := uint64(200000000)
					wantHash := hash
					wantDest := dest
					wantWallet := wallet
					switch bad {
					case "seqno":
						seq++
					case "global":
						global++
					case "mode":
						mode = 128
					case "extra":
						extra = true
					case "amount":
						value++
					case "body":
						wantHash = strings.Repeat("ff", 32)
					case "destination":
						wantDest = wallet
					case "payer":
						wantWallet = dest
					}
					root, _, _ = tokenWalletFixture(t, kind, seq, global, mode, extra)
					if _, e := checkTokenWalletMessage(root, kind, 3, 5, wantWallet, wantDest, value, wantHash); e == nil {
						t.Fatal("malformed signed envelope accepted")
					}
				})
			}
		})
	}
}
