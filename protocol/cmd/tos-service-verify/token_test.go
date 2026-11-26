package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"encoding/hex"
	"github.com/tosnetwork/ai/protocol/internal/purchasefixture"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/purchaseevidence"
)

func TestTokenVerifierUsesTokenSessionAndReportsReadFailure(t *testing.T) {
	purchase := newFixture(t)
	f := files(t, purchase)
	pins := writeFile(t, f.dir, "asset-pins.json", []byte(`[{"Master":"0:`+strings.Repeat("44", 32)+`","Decimals":6}]`))
	previous := openTokenSession
	defer func() { openTokenSession = previous }()
	calls := 0
	openTokenSession = func(_ context.Context, c readConfig) (*openedToken, error) {
		calls++
		if c.actorCodeHash != "tvm-cell-sha256:"+hex.EncodeToString(nativecore.ServiceActorTokenReleaseCodeHash[:]) {
			t.Fatal("token code pin lost")
		}
		return nil, errors.New("token quorum unavailable")
	}
	args := f.arguments(purchase, "--actor", purchasefixture.Actor, "--request-id", "1", "--asset-pins", pins, "--actor-code-hash", "tvm-cell-sha256:"+hex.EncodeToString(nativecore.ServiceActorTokenReleaseCodeHash[:]))
	var out, errout bytes.Buffer
	if code := run(args, &out, &errout); code != exitFail || calls != 1 || !strings.Contains(out.String(), purchaseevidence.TokenVerdictSchema) || !strings.Contains(out.String(), "token quorum unavailable") {
		t.Fatalf("code=%d calls=%d out=%s err=%s", code, calls, out.String(), errout.String())
	}
}
func TestTokenVerifierRefusesUnknownAssetPinFieldsBeforeOpening(t *testing.T) {
	purchase := newFixture(t)
	f := files(t, purchase)
	pins := writeFile(t, f.dir, "pins.json", []byte(`[{"Master":"x","unexpected":1}]`))
	previous := openTokenSession
	defer func() { openTokenSession = previous }()
	openTokenSession = func(context.Context, readConfig) (*openedToken, error) {
		t.Fatal("malformed pins reached RPC")
		return nil, nil
	}
	var out, errout bytes.Buffer
	if code := run(f.arguments(purchase, "--actor", purchasefixture.Actor, "--request-id", "1", "--asset-pins", pins), &out, &errout); code != exitUsage {
		t.Fatalf("code=%d %s", code, errout.String())
	}
}
