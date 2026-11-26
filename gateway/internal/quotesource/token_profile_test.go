package quotesource

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

func tokenProfilePin() toschain.TokenAssetPin {
	return toschain.TokenAssetPin{Master: "0:" + strings.Repeat("31", 32),
		Bridge: "-1:" + strings.Repeat("41", 32), BridgeConfigParam: 79, Decimals: 6,
		SourceChainID: 1, SourceToken: [20]byte{1}, BridgeCodeHash: "tvm-cell-sha256:" + strings.Repeat("42", 32),
		MinterCodeHash: "tvm-cell-sha256:" + strings.Repeat("33", 32), WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("32", 32)}
}

func TestTokenProfileRequiresAndPreservesOwnerPins(t *testing.T) {
	files := newProfileFiles(t, actorCodeHash)
	manifest := testManifest(actorCodeHash)
	decimals := uint8(6)
	manifest.Settlement.Rail = nativecore.ServiceActorTokenRail
	manifest.SupportedAssets = []nativecore.SoftwareWorkAssetV1{{Kind: nativecore.TOSTokenAsset,
		MasterAccountID: bytes.Repeat([]byte{0x31}, 32), WalletCodeHash: bytes.Repeat([]byte{0x32}, 32), Decimals: &decimals}}
	raw, _, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writePrivate(t, filepath.Join(files.directory, "manifest.cbor"), raw)
	document := files.document()
	if _, _, err := LoadProfile(files.write(t, document, 0o600)); err == nil {
		t.Fatal("token profile without owner pins was accepted")
	}
	pin := tokenProfilePin()
	document["token_pins"] = []toschain.TokenAssetPin{pin}
	profile, _, err := LoadProfile(files.write(t, document, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.TokenPins) != 1 || profile.TokenPins[0] != pin {
		t.Fatal("owner asset pins changed during profile loading")
	}
	document["token_pins"] = []toschain.TokenAssetPin{pin, pin, pin}
	if _, _, err := LoadProfile(files.write(t, document, 0o600)); err == nil {
		t.Fatal("more than two asset pins were accepted")
	}
}

func TestNativeProfileRefusesTokenPins(t *testing.T) {
	files := newProfileFiles(t, actorCodeHash)
	document := files.document()
	document["token_pins"] = []toschain.TokenAssetPin{tokenProfilePin()}
	if _, _, err := LoadProfile(files.write(t, document, 0o600)); err == nil {
		t.Fatal("native profile accepted token asset pins")
	}
}
