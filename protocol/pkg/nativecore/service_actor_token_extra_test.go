package nativecore

import (
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"testing"
)

// Every root and referenced field must be exhausted, independently of the
// frozen positive bytes. A suffix cannot become unsigned extension data.
func TestTokenProtocolTrailingCellsRefused(t *testing.T) {
	v := readTokenProtocolVector(t)
	quote, _, err := BuildAcceptedTokenQuoteCommitment(v.Network, v.Proposal)
	if err != nil {
		t.Fatal(err)
	}
	receipt, _, err := BuildSoftwareWorkTokenReceiptCellV1(v.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	for name, root := range map[string]*cell.Cell{"quote": quote, "receipt": receipt} {
		for _, kind := range []string{"root bit", "child bit", "child ref"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				s := root.MustBeginParse()
				bits := s.MustLoadSlice(s.BitsLeft())
				refs := []*cell.Cell{}
				for s.RefsNum() > 0 {
					refs = append(refs, s.MustLoadRef().MustToCell())
				}
				b := cell.BeginCell().MustStoreSlice(bits, root.BitsSize())
				if kind == "root bit" {
					b.MustStoreBoolBit(true)
				}
				for i, ref := range refs {
					if i == 0 && (kind == "child bit" || kind == "child ref") {
						cs := ref.MustBeginParse()
						cb := cell.BeginCell().MustStoreSlice(cs.MustLoadSlice(cs.BitsLeft()), ref.BitsSize())
						for cs.RefsNum() > 0 {
							cb.MustStoreRef(cs.MustLoadRef().MustToCell())
						}
						if kind == "child bit" {
							cb.MustStoreBoolBit(true)
						} else {
							cb.MustStoreRef(cell.BeginCell().EndCell())
						}
						ref = cb.EndCell()
					}
					b.MustStoreRef(ref)
				}
				bad := b.EndCell()
				if name == "quote" {
					if _, err := DecodeAcceptedTokenQuoteV1(bad, v.Network); err == nil {
						t.Fatal("quote suffix accepted")
					}
				} else {
					if _, err := DecodeSoftwareWorkTokenReceiptCellV1(bad); err == nil {
						t.Fatal("receipt suffix accepted")
					}
				}
			})
		}
	}
}
