package buyeragent

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/buyersdk"
)

// Confirmation rules (MCP_BUYER_ADAPTER_V1 section 5.3).
const (
	confirmationDomain = "tos.service.mcp-buyer.confirmation.v2"
	// ConfirmationNonceBytes is the size of the per-presentation nonce.
	ConfirmationNonceBytes = 16
	// ConfirmationLifetime is how long one presentation's code stays valid.
	ConfirmationLifetime = 10 * time.Minute
	// MaxCodeFailures withdraws a purchase after this many wrong codes.
	MaxCodeFailures = 3
)

// ConfirmationFields are the purchase fields a confirmation code binds,
// each in the text form the journal and the purchase record store.
type ConfirmationFields struct {
	TokenFunding    string
	NetworkID       string
	BuyerWallet     string
	Actor           string
	RequestHash     string
	TermsHash       string
	QuoteCommitment string
	PaymentNanoTOS  string
	SourceDigest    string
}

// fieldsOf takes the bound fields from the agent's own records, never from
// a request.
func fieldsOf(record buyersdk.CallRecord, purchase PurchaseRecord) (ConfirmationFields, error) {
	funding, err := tokenConfirmation(record)
	if err != nil {
		return ConfirmationFields{}, err
	}
	return ConfirmationFields{NetworkID: record.NetworkID, BuyerWallet: record.BuyerWallet, Actor: record.Actor,
		RequestHash: record.RequestHash, TermsHash: record.TermsHash, QuoteCommitment: record.QuoteCommitment,
		PaymentNanoTOS: record.PaymentNanoTOS, SourceDigest: purchase.SourceDigest, TokenFunding: funding}, nil
}

// ConfirmationCode derives the code of one presentation:
//
//	SHA-256(domain || 0x00 || nonce || network_id || 0x00 || buyer_wallet ||
//	        0x00 || actor || 0x00 || request_hash || 0x00 || terms_hash ||
//	        0x00 || quote_commitment || 0x00 || payment_nanotos || 0x00 ||
//	        source_digest)
//
// truncated to 8 bytes and written as 16 lowercase hex digits in four
// groups of four joined by "-".
func ConfirmationCode(nonce [ConfirmationNonceBytes]byte, fields ConfirmationFields) string {
	hash := sha256.New()
	domain := confirmationDomain
	if fields.TokenFunding != "" {
		domain = "tos.service.mcp-buyer.confirmation.token.v1"
	}
	hash.Write([]byte(domain))
	hash.Write([]byte{0})
	hash.Write(nonce[:])
	for index, value := range []string{fields.NetworkID, fields.BuyerWallet, fields.Actor, fields.RequestHash,
		fields.TermsHash, fields.QuoteCommitment, fields.PaymentNanoTOS, fields.SourceDigest} {
		if index > 0 {
			hash.Write([]byte{0})
		}
		hash.Write([]byte(value))
	}
	if fields.TokenFunding != "" {
		hash.Write([]byte{0})
		hash.Write([]byte(fields.TokenFunding))
	}
	return groupHex(hex.EncodeToString(hash.Sum(nil)[:8]))
}

// PurchaseReference identifies a purchase across the MCP client and the
// confirmer: the first 16 hex digits of its request hash, grouped. It
// authorizes nothing.
func PurchaseReference(requestHash string) string {
	if len(requestHash) < 16 {
		return ""
	}
	return groupHex(requestHash[:16])
}

func groupHex(digits string) string {
	return digits[0:4] + "-" + digits[4:8] + "-" + digits[8:12] + "-" + digits[12:16]
}

// normalizeTypedCode removes the "-" separators and lowercases. Anything
// that is not then exactly 16 hex digits can never match.
func normalizeTypedCode(typed string) (string, bool) {
	if len(typed) > 64 {
		return "", false
	}
	value := strings.ToLower(strings.ReplaceAll(typed, "-", ""))
	if len(value) != 16 {
		return "", false
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", false
	}
	return value, true
}

// codesMatch compares a typed code with the expected one in constant time.
func codesMatch(expected, typed string) bool {
	normalized, ok := normalizeTypedCode(typed)
	if !ok {
		return false
	}
	want := strings.ReplaceAll(expected, "-", "")
	return subtle.ConstantTimeCompare([]byte(want), []byte(normalized)) == 1
}

// parseNonce decodes a stored nonce.
func parseNonce(text string) ([ConfirmationNonceBytes]byte, error) {
	var nonce [ConfirmationNonceBytes]byte
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != ConfirmationNonceBytes {
		return nonce, errors.New("the stored confirmation nonce is invalid")
	}
	copy(nonce[:], raw)
	return nonce, nil
}
