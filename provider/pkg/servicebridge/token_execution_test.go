package servicebridge

import (
	"context"
	"encoding/json"
	"github.com/tosnetwork/ai/execution/pkg/railgate"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTokenExecutionRefusesAnAlarmOrStaleMonitor(t *testing.T) {
	w := newTokenWorld(t)
	now := w.ChainTime()
	if err := tokenWorkSafety(w.c, "asset-a", w, now); err != nil {
		t.Fatal(err)
	}
	w.report(t, []string{"asset-a"})
	if err := tokenWorkSafety(w.c, "asset-a", w, now); err == nil {
		t.Fatal("alarmed execution admitted")
	}
	// A different asset's alarm never blocks this actor.
	w.report(t, []string{"foreign-asset"})
	if err := tokenWorkSafety(w.c, "asset-a", w, now); err != nil {
		t.Fatal(err)
	}
	w.report(t, nil)
	if err := tokenWorkSafety(w.c, "asset-a", w, now.Add(301*time.Second)); err == nil {
		t.Fatal("stale monitor authorized execution")
	}
}

func TestTokenLifecycleUsesTheTokenDomainAndCodeProfile(t *testing.T) {
	s := &TOSCTLLifecycle{tokenProfile: "test", config: "config", wallet: "owner"}
	var captured []string
	s.run = func(_ context.Context, args []string) ([]byte, error) {
		captured = append([]string(nil), args...)
		return []byte(`{}`), nil
	}
	if err := s.Respond(context.Background(), "0:"+strings.Repeat("11", 32), 1, [32]byte{1}, "attestor"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(captured, " ")
	if !strings.Contains(joined, "agent service-token") || !strings.Contains(joined, "--code-profile test") || !strings.Contains(joined, "--attestor-controller attestor") {
		t.Fatal(joined)
	}
}

func TestTokenExecutionRefusesMissingMonitor(t *testing.T) {
	w := newTokenWorld(t)
	if err := os.Rename(w.c.Token.MonitorReport, w.c.Token.MonitorReport+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := tokenWorkSafety(w.c, "asset-a", w, w.ChainTime()); err == nil {
		t.Fatal("missing report authorized execution")
	}
}

func TestTokenExecutionRefusesLocalAdmissionPause(t *testing.T) {
	w := newTokenWorld(t)
	if _, _, err := PauseAdmission(w.c.StateDir, "operator pause", w.ChainTime()); err != nil {
		t.Fatal(err)
	}
	if err := tokenWorkSafety(w.c, "asset-a", w, w.ChainTime()); err == nil {
		t.Fatal("locally paused execution admitted")
	}
}

type tokenResponseSession struct {
	railgate.Session
	tokenWorld *tokenWorld
}
type tokenResponseReader struct{ session tokenResponseSession }

func (r tokenResponseReader) BeginSession(context.Context) (railgate.Session, error) {
	return r.session, nil
}

func TestTokenRespondFinalizedBindsHashAndHistoryHead(t *testing.T) {
	for _, wrong := range []string{"none", "response", "head"} {
		t.Run(wrong, func(t *testing.T) {
			w := newTokenWorld(t)
			response := strings.Repeat("2a", 32)
			w.account.LastTransaction = toschain.ActorTxID{LT: 10, Hash: strings.Repeat("a", 64)}
			w.history = &toschain.TokenActorHistory{Result: toschain.HistoryComplete, Head: w.account.LastTransaction, Transactions: []toschain.TokenActorTransaction{{TookEffect: true, Kind: toschain.ActorTxRespond, RequestID: 7, ResponseHash: response}}}
			if wrong == "response" {
				w.history.Transactions[0].ResponseHash = strings.Repeat("2b", 32)
			}
			if wrong == "head" {
				w.history.Head.LT--
			}
			p := &Provider{config: ProviderConfig{History: tokenResponseReader{tokenResponseSession{tokenWorld: w}}}}
			ok, err := p.respondFinalized(context.Background(), ProviderRecord{Actor: w.account.Address, AssetMaster: "token", RequestID: 7, ResponseHash: response})
			if wrong == "none" {
				if err != nil || !ok {
					t.Fatalf("valid response refused: %v", err)
				}
			} else if err == nil || ok {
				t.Fatalf("%s mismatch accepted", wrong)
			}
		})
	}
}

func (s tokenResponseSession) Checkpoint() uint64   { return s.tokenWorld.Checkpoint() }
func (s tokenResponseSession) ChainTime() time.Time { return s.tokenWorld.ChainTime() }

func (s tokenResponseSession) ReadTokenActor(ctx context.Context, actor string) (*toschain.TokenActorAccount, bool, error) {
	return s.tokenWorld.ReadTokenActor(ctx, actor)
}
func (s tokenResponseSession) TokenHistory(ctx context.Context, actor string, anchor *toschain.ActorTxID) (*toschain.TokenActorHistory, error) {
	return s.tokenWorld.TokenHistory(ctx, actor, anchor)
}

func TestTokenExecutionIgnoresNonEmergencyMonitorAlarms(t *testing.T) {
	w := newTokenWorld(t)
	raw, err := os.ReadFile(w.c.Token.MonitorReport)
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	report["alarms"] = []any{map[string]any{"asset": "asset-a", "code": "redemption_blocked"}}
	raw, err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.c.Token.MonitorReport, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := tokenWorkSafety(w.c, "asset-a", w, w.ChainTime()); err != nil {
		t.Fatal(err)
	}
}
