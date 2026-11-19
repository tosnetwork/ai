package nativecore

import (
	"encoding/hex"
	"testing"
)

func TestServiceActorCodeHashesAreTheTosManifestPins(t *testing.T) {
	// tos crypto/smartcont/tos-service-actor-v1.release.json and
	// tos-service-actor-v1-test.release.json.
	if got := hex.EncodeToString(ServiceActorReleaseCodeHash[:]); got != "0594f9a5743440f9c5f63913ab790c0ea6f4fd5c627d9962d63e09428e42aa0c" {
		t.Errorf("release code hash %s", got)
	}
	if got := hex.EncodeToString(ServiceActorTestProfileCodeHash[:]); got != "79a566f5f4281f7abe59cd1c16a7bc3b2d990e840f42b00d55cb0ae4b0545960" {
		t.Errorf("test-profile code hash %s", got)
	}
	if ServiceActorReleaseCodeHash == ServiceActorTestProfileCodeHash {
		t.Error("the test-profile code hash equals the release code hash")
	}
}

func TestServiceActorMinimumWindowFollowsTheCode(t *testing.T) {
	var zero, other [32]byte
	other[0] = 1
	cases := []struct {
		name string
		code [32]byte
		want uint32
	}{
		{"release", ServiceActorReleaseCodeHash, 3_600},
		{"test profile", ServiceActorTestProfileCodeHash, 600},
		{"zero", zero, 3_600},
		{"other", other, 3_600},
	}
	for _, c := range cases {
		if got := ServiceActorMinimumWindowSecondsFor(c.code); got != c.want {
			t.Errorf("%s: minimum window %d, want %d", c.name, got, c.want)
		}
	}
	// One flipped bit of the test-profile hash is just another code.
	near := ServiceActorTestProfileCodeHash
	near[31] ^= 1
	if got := ServiceActorMinimumWindowSecondsFor(near); got != ServiceActorMinimumWindowSeconds {
		t.Errorf("a near test-profile hash gets %d", got)
	}
}
