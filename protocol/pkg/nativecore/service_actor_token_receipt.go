package nativecore

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// SoftwareWorkTokenReceiptV1 is schema 2; the embedded shared fields retain
// schema 1's validation, while the extra account id binds the exact asset.
type SoftwareWorkTokenReceiptV1 struct {
	SoftwareWorkReceiptV1
	AssetMaster [32]byte
}

func BuildSoftwareWorkTokenReceiptCellV1(value SoftwareWorkTokenReceiptV1) (*cell.Cell, string, error) {
	if value.AssetMaster == ([32]byte{}) {
		return nil, "", errors.New("zero Receipt asset master")
	}
	base, _, err := BuildSoftwareWorkReceiptCellV1(value.SoftwareWorkReceiptV1)
	if err != nil {
		return nil, "", err
	}
	b, err := beginOrdinary(base, "Receipt")
	if err != nil {
		return nil, "", err
	}
	if _, err = b.LoadSlice(144); err != nil {
		return nil, "", err
	}
	binding, err := loadRefCell(b, "Receipt binding")
	if err != nil {
		return nil, "", err
	}
	outcome, err := loadRefCell(b, "Receipt outcome")
	if err != nil {
		return nil, "", err
	}
	evidence, err := loadRefCell(b, "Receipt evidence")
	if err != nil {
		return nil, "", err
	}
	economic, err := loadRefCell(b, "Receipt economic")
	if err != nil {
		return nil, "", err
	}
	e, err := beginOrdinary(economic, "Receipt economic")
	if err != nil {
		return nil, "", err
	}
	amount, err := e.LoadBigUInt(128)
	if err != nil {
		return nil, "", err
	}
	provider, err := loadHash(e)
	if err != nil {
		return nil, "", err
	}
	economic = cell.BeginCell().MustStoreBigUInt(amount, 128).MustStoreSlice(value.AssetMaster[:], 256).MustStoreSlice(provider[:], 256).EndCell()
	root := cell.BeginCell().MustStoreUInt(softwareWorkReceiptMagic, 32).MustStoreUInt(2, 16).MustStoreUInt(value.CompletedAt, 64).MustStoreInt(int64(value.ExitCode), 32).MustStoreRef(binding).MustStoreRef(outcome).MustStoreRef(evidence).MustStoreRef(economic).EndCell()
	return root, digestString(root.Hash()), nil
}

func DecodeSoftwareWorkTokenReceiptCellV1(root *cell.Cell) (SoftwareWorkTokenReceiptV1, error) {
	var out SoftwareWorkTokenReceiptV1
	s, err := beginOrdinary(root, "token Receipt")
	if err != nil {
		return out, err
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != softwareWorkReceiptMagic {
		return out, errors.New("invalid Receipt magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != 2 {
		return out, errors.New("unsupported token Receipt schema")
	}
	completed, err := s.LoadUInt(64)
	if err != nil {
		return out, err
	}
	exit, err := s.LoadInt(32)
	if err != nil {
		return out, err
	}
	binding, err := loadRefCell(s, "Receipt binding")
	if err != nil {
		return out, err
	}
	outcome, err := loadRefCell(s, "Receipt outcome")
	if err != nil {
		return out, err
	}
	evidence, err := loadRefCell(s, "Receipt evidence")
	if err != nil {
		return out, err
	}
	economic, err := loadRefCell(s, "Receipt economic")
	if err != nil {
		return out, err
	}
	if err = exhausted(s, "token Receipt"); err != nil {
		return out, err
	}
	e, err := beginOrdinary(economic, "Receipt economic")
	if err != nil {
		return out, err
	}
	amount, err := e.LoadBigUInt(128)
	if err != nil {
		return out, err
	}
	if out.AssetMaster, err = loadHash(e); err != nil {
		return out, err
	}
	provider, err := loadHash(e)
	if err != nil {
		return out, err
	}
	if err = exhausted(e, "Receipt economic"); err != nil {
		return out, err
	}
	// The shared cells have identical layouts. Reusing their strict decoder does
	// not accept schema 1 on the wire: the outer check above requires schema 2.
	commonEconomic := cell.BeginCell().MustStoreBigUInt(amount, 128).MustStoreSlice(provider[:], 256).EndCell()
	commonRoot := cell.BeginCell().MustStoreUInt(softwareWorkReceiptMagic, 32).MustStoreUInt(1, 16).MustStoreUInt(completed, 64).MustStoreInt(exit, 32).MustStoreRef(binding).MustStoreRef(outcome).MustStoreRef(evidence).MustStoreRef(commonEconomic).EndCell()
	out.SoftwareWorkReceiptV1, err = DecodeSoftwareWorkReceiptCellV1(commonRoot)
	if err != nil {
		return out, err
	}
	rebuilt, _, err := BuildSoftwareWorkTokenReceiptCellV1(out)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return out, errors.New("token Receipt is not canonical")
	}
	return out, nil
}

// TokenReceiptMatchesQuote is the asset/amount part of the custody policy.
// It does not prove execution or replace finalized response verification.
func TokenReceiptMatchesQuote(receipt SoftwareWorkTokenReceiptV1, quote *AcceptedQuoteTermsV1) error {
	if _, _, err := BuildSoftwareWorkTokenReceiptCellV1(receipt); err != nil {
		return err
	}
	if quote == nil || quote.Proposal == nil {
		return errors.New("missing token Quote")
	}
	rail, err := ParseServiceActorTokenQuoteRail(quote.Proposal)
	if err != nil {
		return err
	}
	if receipt.ChargedAtomicAmount != rail.PriceAtomic.String() || !bytes.Equal(receipt.AssetMaster[:], rail.Asset.Master.AccountId) || receipt.ProviderAgentID != quote.Proposal.ProviderAgentId {
		return errors.New("Receipt asset, charge or provider differs from token Quote")
	}
	_, commitment, err := BuildAcceptedTokenQuoteCommitment(quote.Network, quote.Proposal)
	if err != nil {
		return err
	}
	if receipt.QuoteCommitment != commitment {
		return errors.New("Receipt token Quote commitment mismatch")
	}

	return nil
}
