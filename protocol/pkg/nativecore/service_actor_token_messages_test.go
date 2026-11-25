package nativecore

import (
	"math/big"
	"strings"
	"testing"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func tokenReportedFixture(t *testing.T, mode string) *cell.Cell {
	t.Helper()
	opcode := uint64(0x52545231)
	if mode == "opcode" {
		opcode++
	}
	b := cell.BeginCell().MustStoreUInt(opcode, 32).MustStoreUInt(7, 64)
	amount := big.NewInt(100)
	if mode == "zero amount" {
		amount.SetInt64(0)
	}
	if err := storeServiceActorCoins(b, amount); err != nil {
		t.Fatal(err)
	}
	dest, err := StandardAddress("0:" + strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	if mode == "destination" {
		dest, err = StandardAddress("-1:" + strings.Repeat("11", 32))
		if err != nil {
			t.Fatal(err)
		}
	}
	b.MustStoreSlice(dest.Bits, dest.BitLen)
	if mode == "response" {
		b.MustStoreUInt(0, 2)
	} else {
		response := dest
		if mode == "masterchain response" {
			response, err = StandardAddress("-1:" + strings.Repeat("22", 32))
			if err != nil {
				t.Fatal(err)
			}
		}
		b.MustStoreSlice(response.Bits, response.BitLen)
	}
	if err := storeServiceActorCoins(b, big.NewInt(200)); err != nil {
		t.Fatal(err)
	}
	forward := big.NewInt(0)
	if mode == "forward" {
		forward.SetInt64(1)
	}
	if err := storeServiceActorCoins(b, forward); err != nil {
		t.Fatal(err)
	}
	b.MustStoreBoolBit(mode == "referenced payload")
	if mode == "trailing bit" {
		b.MustStoreBoolBit(true)
	}
	if mode == "trailing ref" || mode == "referenced payload" {
		b.MustStoreRef(cell.BeginCell().EndCell())
	}
	return b.EndCell()
}
func TestTokenReportedTransferStrictPayoutShape(t *testing.T) {
	r, err := DecodeServiceActorTokenReportedTransfer(tokenReportedFixture(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if r.QueryID != 7 || r.Amount.Cmp(big.NewInt(100)) != 0 || r.ReportTOSAmount.Cmp(big.NewInt(200)) != 0 || r.ForwardTOSAmount.Sign() != 0 || r.Destination.Text() != r.ResponseDestination.Text() {
		t.Fatal("reported transfer fields differ")
	}
	masterchain, err := DecodeServiceActorTokenReportedTransfer(tokenReportedFixture(t, "masterchain response"))
	if err != nil || masterchain.ResponseDestination.Workchain != -1 {
		t.Fatalf("canonical masterchain requester refused: %v", err)
	}
	for _, mode := range []string{"opcode", "zero amount", "destination", "response", "forward", "referenced payload", "trailing bit", "trailing ref"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := DecodeServiceActorTokenReportedTransfer(tokenReportedFixture(t, mode)); err == nil {
				t.Fatalf("accepted %s", mode)
			}
		})
	}
}
