package railwork

import (
	"encoding/hex"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func TestTokenResultRequiresSchemaTwoAndItsExactAsset(t *testing.T) {
	doc := loadVectors(t)
	result := vectorResult(t, doc)
	common, _, err := DecodeReceipt(result.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	var asset [32]byte
	for i := range asset {
		asset[i] = 0xab
	}
	binding := vectorReceiptBinding(t, doc)
	binding.AssetMaster = &asset
	root, _, err := nativecore.BuildSoftwareWorkTokenReceiptCellV1(nativecore.SoftwareWorkTokenReceiptV1{SoftwareWorkReceiptV1: common, AssetMaster: asset})
	if err != nil {
		t.Fatal(err)
	}
	var finalized [32]byte
	copy(finalized[:], root.Hash())
	result.Receipt = root.ToBOC()
	result.Header.ResponseHash = hex.EncodeToString(finalized[:])
	if err := ValidateResult(result, binding, finalized); err != nil {
		t.Fatal(err)
	}
	decoded, storedAsset, hash, err := DecodeStoredReceipt(result.Receipt)
	if err != nil || storedAsset == nil || *storedAsset != asset || hash != finalized || decoded.ChargedAtomicAmount != common.ChargedAtomicAmount {
		t.Fatalf("stored result %v %v", storedAsset, err)
	}
	for _, which := range []string{"wrong asset", "native binding", "native receipt", "noncanonical", "wrong response"} {
		t.Run(which, func(t *testing.T) {
			altered, b := result, binding
			switch which {
			case "wrong asset":
				other := asset
				other[0] ^= 1
				b.AssetMaster = &other
			case "native binding":
				b.AssetMaster = nil
			case "native receipt":
				altered = vectorResult(t, doc)
			case "noncanonical":
				altered.Receipt = root.ToBOCWithOptions(cell.BOCSerializeOptions{})
			case "wrong response":
				altered.Header.ResponseHash = "00" + altered.Header.ResponseHash[2:]
			}
			if err := ValidateResult(altered, b, finalized); err == nil {
				t.Fatal("mismatched token result accepted")
			}
		})
	}
}
func TestReceiptBuilderAndAttestorKeepTokenSchemaSeparate(t *testing.T) {
	doc := loadVectors(t)
	result := vectorResult(t, doc)
	receipt, _, err := DecodeReceipt(result.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	binding := vectorReceiptBinding(t, doc)
	var asset [32]byte
	asset[0] = 1
	binding.AssetMaster = &asset
	outcome := Outcome{ResultDigest: receipt.ResultDigest, ArtifactDigest: receipt.ArtifactDigest, ReportDigest: receipt.ReportDigest, CompletedAtUnix: receipt.CompletedAt}
	root, hash, err := BuildReceipt(binding, outcome)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecodeReceipt(root.ToBOC()); err == nil {
		t.Fatal("token receipt decoded as native")
	}
	if actual, err := CheckAttestable(root.ToBOC(), binding, outcome); err != nil || actual != hash {
		t.Fatalf("token attestation %v", err)
	}
	binding.AssetMaster = nil
	if _, err := CheckAttestable(root.ToBOC(), binding, outcome); err == nil {
		t.Fatal("native attestor accepted token schema")
	}
}
