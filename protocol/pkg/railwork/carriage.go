package railwork

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

// ErrQuoteNotCarriable reports a Quote whose package a rail task cannot
// carry (section 5.1). Such a Quote must not be published, proposed or
// paid for: the buyer could never send its task.
var ErrQuoteNotCarriable = errors.New("railwork: the Quote package is larger than a rail task can carry")

// maxProposalIDBytes is the longest proposal_id portable Quote validation
// accepts.
const maxProposalIDBytes = 256

// CheckCarriablePackage refuses, for an Agent Packet transport (mode 2), a
// serialized Quote package of more than MaxPackageBytes. Other transports
// do not carry the package in a rail task and pass.
func CheckCarriablePackage(packageBytes int, transport nativecore.TransportBindingV1) error {
	if packageBytes <= 0 {
		return fmt.Errorf("%w: an empty Quote package", ErrInvalidInput)
	}
	if transport.SecurityMode != nativecore.TransportAgentPacket {
		return nil
	}
	if packageBytes > MaxPackageBytes {
		return fmt.Errorf("%w: %d bytes, over the %d-byte bound", ErrQuoteNotCarriable, packageBytes, MaxPackageBytes)
	}
	return nil
}

// CheckCarriableQuote is CheckCarriablePackage for a Quote package value,
// measured as the canonical bytes a buyer stores and sends.
func CheckCarriableQuote(value *nativev1.QuoteProposalPackageV1, transport nativecore.TransportBindingV1) error {
	if value == nil {
		return fmt.Errorf("%w: no Quote package", ErrInvalidInput)
	}
	return CheckCarriablePackage(proto.Size(value), transport)
}

// CheckCarriableManifest refuses, for an Agent Packet transport (mode 2), a
// canonical manifest whose Quotes could exceed MaxPackageBytes. It sizes
// the package of that manifest and transport with a Quote Proposal whose
// every field is at its maximum (section 5.1), so any Quote a provider can
// propose for the manifest fits.
func CheckCarriableManifest(manifestCBOR []byte, transport nativecore.TransportBindingV1) error {
	if transport.SecurityMode != nativecore.TransportAgentPacket {
		return nil
	}
	size, err := largestQuoteSize(manifestCBOR, transport)
	if err != nil {
		return err
	}
	return CheckCarriablePackage(size, transport)
}

// largestQuoteSize is the serialized size of the largest Quote package a
// provider can propose for a manifest and transport.
func largestQuoteSize(manifestCBOR []byte, transport nativecore.TransportBindingV1) (int, error) {
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(manifestCBOR)
	if err != nil {
		return 0, fmt.Errorf("%w: the manifest does not decode: %w", ErrInvalidInput, err)
	}
	root, transportDigest, err := nativecore.BuildTransportBindingCellV1(transport)
	if err != nil {
		return 0, fmt.Errorf("%w: the transport binding does not build: %w", ErrInvalidInput, err)
	}
	largestAmount := new(big.Int).Sub(nativecore.MaxServiceActorCoins, big.NewInt(1)).String()
	hex64 := strings.Repeat("f", 64)
	worst := &nativev1.QuoteProposalPackageV1{
		Proposal: &nativev1.QuoteProposalV1{
			ProposalId: strings.Repeat("p", maxProposalIDBytes), CapabilityId: "cap_" + hex64,
			CapabilityVersion: manifest.Version, ProviderAgentId: "agent_" + hex64,
			ManifestDigest: "sha256:" + hex64, TransportBindingDigest: transportDigest,
			ExpiresAtUnixSeconds: math.MaxUint64,
			Actor:                &nativev1.TOSAccountAddressV1{AccountId: make([]byte, 32)},
			ActorCodeHash:        "tvm-cell-sha256:" + hex64, PolicyVersion: math.MaxUint32, TermsHash: hex64,
			PriceNanotos: largestAmount, StorageFeeNanotos: largestAmount, AttestorKeyId: "mldsa44:" + hex64,
		},
		CanonicalManifestCbor: manifestCBOR, TransportBindingBoc: root.ToBOC(),
	}
	return proto.Size(worst), nil
}
