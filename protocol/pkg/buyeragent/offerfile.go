package buyeragent

import (
	"encoding/base64"
	"errors"

	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/pkg/quoteexchange"
)

// OfferFileSchema names the offer file a provider hands a buyer
// (section 3.3): the Capability version, its manifest bytes and,
// optionally, the provider's relay key card.
const OfferFileSchema = "tos.openfox.rail-offer.v2"

// MaxOfferFileBytes bounds an offer file. A carriable manifest is far
// smaller (section 7.1 item 2), and the Base64 of the bound fits one agent
// request.
const MaxOfferFileBytes = 256 << 10

// offerFileJSON is the offer file's encoding. Every field is a hint: the
// provider is the Capability's finalized owner, the manifest must hash to
// the finalized digest, and the card is verified against finalized state
// before it is kept.
type offerFileJSON struct {
	Schema          string `json:"schema"`
	CapabilityID    string `json:"capability_id"`
	Version         string `json:"version"`
	ProviderAgentID string `json:"provider_agent_id"`
	ManifestDigest  string `json:"manifest_digest"`
	ManifestCBOR    string `json:"manifest_cbor_base64"`
	RelayKeyCard    string `json:"relay_key_card_base64,omitempty"`
	UpdatedUnix     int64  `json:"updated_unix"`
}

// offerFile is a decoded offer file.
type offerFile struct {
	CapabilityID string
	Version      string
	Manifest     []byte
	// KeyCard is the provider card packet JSON, or nil.
	KeyCard []byte
}

// decodeOfferFile strictly decodes offer-file bytes: unknown fields,
// trailing data, another schema, non-canonical Base64 and values outside
// their bounds are refused. It checks shapes only. The caller bounds raw
// to MaxOfferFileBytes.
func decodeOfferFile(raw []byte) (offerFile, error) {
	var file offerFileJSON
	if err := jsonstrict.Decode(raw, &file); err != nil {
		return offerFile{}, errors.New("the offer file is not a strict offer record")
	}
	if file.Schema != OfferFileSchema {
		return offerFile{}, errors.New("the offer file names another schema")
	}
	if !capabilityIDPattern.MatchString(file.CapabilityID) || !validVersion(file.Version) ||
		!agentIDPattern.MatchString(file.ProviderAgentID) || !manifestDigestPattern.MatchString(file.ManifestDigest) {
		return offerFile{}, errors.New("the offer file names an invalid Capability, version, provider or digest")
	}
	manifest, err := canonicalBase64(file.ManifestCBOR, MaxManifestBytes)
	if err != nil {
		return offerFile{}, errors.New("the offer file's manifest is not canonical Base64 within its bound")
	}
	offer := offerFile{CapabilityID: file.CapabilityID, Version: file.Version, Manifest: manifest}
	if file.RelayKeyCard != "" {
		if offer.KeyCard, err = canonicalBase64(file.RelayKeyCard, quoteexchange.MaxProviderKeyCardBytes); err != nil {
			return offerFile{}, errors.New("the offer file's key card is not canonical Base64 within its bound")
		}
	}
	return offer, nil
}

// canonicalBase64 decodes non-empty canonical standard Base64 of at most
// limit bytes.
func canonicalBase64(text string, limit int) ([]byte, error) {
	if text == "" || len(text) > base64.StdEncoding.EncodedLen(limit) {
		return nil, errors.New("empty or over its bound")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(raw) > limit || base64.StdEncoding.EncodeToString(raw) != text {
		return nil, errors.New("not canonical standard Base64")
	}
	return raw, nil
}

// validVersion reports a Capability version of 1 to 128 bytes of 0x21 to
// 0x7e (section 7.1 item 2).
func validVersion(version string) bool {
	if len(version) == 0 || len(version) > 128 {
		return false
	}
	for index := 0; index < len(version); index++ {
		if version[index] < 0x21 || version[index] > 0x7e {
			return false
		}
	}
	return true
}
