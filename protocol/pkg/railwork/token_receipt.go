package railwork

import (
	"bytes"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// DecodeReceiptForAsset requires the receipt schema and asset selected by the
// buyer's durable purchase. A token receipt can never satisfy a native purchase.
func DecodeReceiptForAsset(boc []byte, asset *[32]byte) (nativecore.SoftwareWorkReceiptV1, [32]byte, error) {
	if asset == nil {
		return DecodeReceipt(boc)
	}
	token, hash, err := decodeTokenReceipt(boc)
	if err != nil {
		return nativecore.SoftwareWorkReceiptV1{}, [32]byte{}, err
	}
	if *asset == ([32]byte{}) || token.AssetMaster != *asset {
		return nativecore.SoftwareWorkReceiptV1{}, [32]byte{}, notAccepted("the Receipt names another token asset")
	}
	return token.SoftwareWorkReceiptV1, hash, nil
}

func decodeTokenReceipt(boc []byte) (nativecore.SoftwareWorkTokenReceiptV1, [32]byte, error) {
	var hash [32]byte
	if len(boc) == 0 || len(boc) > MaxReceiptBytes {
		return nativecore.SoftwareWorkTokenReceiptV1{}, hash, notAccepted("the Receipt is outside its bounds")
	}
	roots, err := cell.FromBOCMultiRoot(boc)
	if err != nil || len(roots) != 1 || roots[0] == nil {
		return nativecore.SoftwareWorkTokenReceiptV1{}, hash, notAccepted("the token Receipt does not decode to exactly one root")
	}
	root := roots[0]
	if !bytes.Equal(root.ToBOC(), boc) {
		return nativecore.SoftwareWorkTokenReceiptV1{}, hash, notAccepted("the token Receipt BOC is not canonical")
	}
	token, err := nativecore.DecodeSoftwareWorkTokenReceiptCellV1(root)
	if err != nil {
		return nativecore.SoftwareWorkTokenReceiptV1{}, hash, notAccepted("the token Receipt does not decode")
	}
	copy(hash[:], root.Hash())
	return token, hash, nil
}

// DecodeStoredReceipt checks a retained receipt's canonical encoding and reports
// its schema's asset. The caller must compare that asset with the purchase before
// exposing an accepted result; this function alone does not establish acceptance.
func DecodeStoredReceipt(boc []byte) (nativecore.SoftwareWorkReceiptV1, *[32]byte, [32]byte, error) {
	native, hash, err := DecodeReceipt(boc)
	if err == nil {
		return native, nil, hash, nil
	}
	token, hash, err := decodeTokenReceipt(boc)
	if err != nil {
		return nativecore.SoftwareWorkReceiptV1{}, nil, [32]byte{}, err
	}
	asset := token.AssetMaster
	return token.SoftwareWorkReceiptV1, &asset, hash, nil
}
