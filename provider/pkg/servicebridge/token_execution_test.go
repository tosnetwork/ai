package servicebridge

import (
	"context"
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
