package provideragent

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// Confirmation rules (section 5.3).
const (
	confirmationDomain = "tos.service.mcp-provider.confirmation.v1"
	// confirmationNonceBytes is the size of the per-presentation nonce.
	confirmationNonceBytes = 16
	// ConfirmationLifetime is how long one presentation's code stays valid.
	ConfirmationLifetime = 10 * time.Minute
	// MaxCodeFailures cancels an action after this many wrong codes.
	MaxCodeFailures = 3
)

// confirmationFields are what a code binds, each as the agent's own
// records hold it.
type confirmationFields struct {
	NetworkID       string
	ProviderAgentID string
	OwnerWallet     string
	Kind            string
	ActionID        string
	PreviewDigest   string
}

// confirmationCode derives the code of one presentation:
//
//	SHA-256(domain || 0x00 || nonce || network_id || 0x00 ||
//	        provider_agent_id || 0x00 || owner_wallet || 0x00 || action_kind ||
//	        0x00 || action_id || 0x00 || preview_digest)
//
// truncated to 8 bytes and written as 16 lowercase hex digits in four
// groups of four joined by "-".
func confirmationCode(nonce [confirmationNonceBytes]byte, fields confirmationFields) string {
	hash := sha256.New()
	hash.Write([]byte(confirmationDomain))
	hash.Write([]byte{0})
	hash.Write(nonce[:])
	for index, value := range []string{fields.NetworkID, fields.ProviderAgentID, fields.OwnerWallet, fields.Kind,
		fields.ActionID, fields.PreviewDigest} {
		if index > 0 {
			hash.Write([]byte{0})
		}
		hash.Write([]byte(value))
	}
	return groupHex(hex.EncodeToString(hash.Sum(nil)[:8]))
}

// codesMatch compares a typed code with the expected one in constant time,
// after removing the "-" separators and lowercasing. Anything that is not
// then exactly 16 hex digits never matches.
func codesMatch(expected, typed string) bool {
	if len(typed) > 64 {
		return false
	}
	normalized := strings.ToLower(strings.ReplaceAll(typed, "-", ""))
	if len(normalized) != 16 {
		return false
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return false
	}
	want := strings.ReplaceAll(expected, "-", "")
	return subtle.ConstantTimeCompare([]byte(want), []byte(normalized)) == 1
}

func parseNonce(text string) ([confirmationNonceBytes]byte, error) {
	var nonce [confirmationNonceBytes]byte
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != confirmationNonceBytes {
		return nonce, errors.New("the stored confirmation nonce is invalid")
	}
	copy(nonce[:], raw)
	return nonce, nil
}
