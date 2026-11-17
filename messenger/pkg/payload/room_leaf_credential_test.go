package payload

import (
	"bytes"
	"strings"
	"testing"
)

// A room.invite carries the authority's leaf credential and a
// room.key-package the joiner's, each 1 .. 512 bytes (section 11.2).
func TestRoomPayloadsBoundTheLeafCredential(t *testing.T) {
	invite := func(credential []byte) RoomInvite {
		return RoomInvite{RoomID: "room_" + strings.Repeat("9", 64), InviteeAgentID: "agent_" + strings.Repeat("a", 64),
			Purpose: "planning", ExpiresAtUnix: 1_800_000_000, AuthorityLeafCredential: credential}
	}
	keyPackage := func(credential []byte) RoomKeyPackage {
		return RoomKeyPackage{RoomID: "room_" + strings.Repeat("9", 64), DeviceCredentialJSON: []byte(`{"schema":"credential"}`),
			LeafCredential: credential}
	}
	maximal := bytes.Repeat([]byte{0xa5}, MaxLeafCredentialBytes)
	for name, value := range map[string]Payload{"invite": invite(maximal), "key package": keyPackage(maximal)} {
		encoded, err := Encode(value)
		if err != nil {
			t.Fatalf("%s at the bound: %v", name, err)
		}
		kind := "room.invite"
		if name == "key package" {
			kind = "room.key-package"
		}
		decoded, err := Decode(kind, encoded)
		if err != nil {
			t.Fatalf("%s decode: %v", name, err)
		}
		var credential []byte
		switch typed := decoded.(type) {
		case RoomInvite:
			credential = typed.AuthorityLeafCredential
		case RoomKeyPackage:
			credential = typed.LeafCredential
		default:
			t.Fatalf("%s decoded as %T", name, decoded)
		}
		if !bytes.Equal(credential, maximal) {
			t.Fatalf("%s lost its leaf credential", name)
		}
	}
	for name, value := range map[string]Payload{
		"invite without credential":       invite(nil),
		"invite over the bound":           invite(append(maximal, 0)),
		"key package without credential":  keyPackage(nil),
		"key package over the bound":      keyPackage(append(maximal, 0)),
		"key package without device cred": RoomKeyPackage{RoomID: "room_" + strings.Repeat("9", 64), LeafCredential: maximal},
	} {
		if _, err := Encode(value); err == nil {
			t.Fatalf("%s: encoded", name)
		}
	}
}
