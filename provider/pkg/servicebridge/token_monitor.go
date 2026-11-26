package servicebridge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
)

type TokenMonitorReport struct {
	Schema     string `json:"schema"`
	Checkpoint struct {
		Height uint64 `json:"height"`
		Hash   string `json:"hash"`
		Utime  uint64 `json:"utime"`
	} `json:"checkpoint"`
	PauseAssets []string `json:"provider_pause_assets"`
}

// The monitor is a trusted owner-configured observation, never a model input.
// Unknown report fields carry monitoring detail, not signing parameters.
func readTokenMonitor(c NodeConfig, point uint64, now int64) (map[string]bool, error) {
	if c.Token == nil {
		return nil, errors.New("no token monitoring configuration")
	}
	// readJSON enforces strict objects; the full report includes alarm/outbox
	// details, so decode its bounded JSON tree first and select only the hook.
	var raw map[string]json.RawMessage
	data, err := readPrivateFile(c.Token.MonitorReport, 8<<20)
	if err != nil {
		return nil, err
	}
	if err := agentsocket.DecodeParams(data, &raw); err != nil {
		return nil, err
	}
	var report TokenMonitorReport
	for key, dst := range map[string]any{"schema": &report.Schema, "checkpoint": &report.Checkpoint, "provider_pause_assets": &report.PauseAssets} {
		data, ok := raw[key]
		if !ok {
			return nil, errors.New("monitor report missing provider hook")
		}
		if err := json.Unmarshal(data, dst); err != nil {
			return nil, err
		}
	}
	age := c.Token.MaxReportAgeSeconds
	if age == 0 {
		age = 300
	}
	if report.Schema != "tos-settlement-report/1" || report.Checkpoint.Height > point || report.Checkpoint.Utime > uint64(now) || now < 0 || uint64(now)-report.Checkpoint.Utime > uint64(age) || !hex64Pattern.MatchString(report.Checkpoint.Hash) || len(report.PauseAssets) > 64 {
		return nil, errors.New("monitor report is stale, future or malformed")
	}
	result := map[string]bool{}
	for _, label := range report.PauseAssets {
		if !tokenLabel.MatchString(label) || result[label] {
			return nil, errors.New("invalid duplicate monitor asset label")
		}
		result[label] = true
	}
	return result, nil
}

// CheckTokenSafety checks every configured actor without changing another
// asset's authority. Only emergency reports clear active on chain. Floor holds
// prevent new admission locally; neither hold is automatically lifted on chain.
func CheckTokenSafety(ctx context.Context, c NodeConfig, env TokenEnv) error {
	env.fill()
	if c.Token == nil {
		return nil
	}
	if err := c.Token.Validate(); err != nil {
		return err
	}
	var failures []error
	for _, a := range c.Token.Actors {
		s, err := env.Begin(ctx, c, a)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		alerts, err := readTokenMonitor(c, s.Checkpoint(), s.ChainTime().Unix())
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !alerts[a.AssetID] {
			continue
		}
		account, _, err := s.ReadTokenActor(ctx, a.Address)
		if err != nil || account == nil || account.Data == nil {
			failures = append(failures, errors.New("cannot read alarmed token actor"))
			continue
		}
		if !account.Data.Active {
			continue
		}
		keyHash := sha256.Sum256([]byte(fmt.Sprintf("token-auto-pause:%s:%d", a.Address, account.Data.Policy.PolicyVersion)))
		key := hex.EncodeToString(keyHash[:])
		in := TokenActionInput{Actor: a.Address, Operation: "pause", IdempotencyKey: key}
		// The same snapshot constructs the pause; apply revalidates freshly and
		// refuses a changed body. A monitor can only reduce configured authority.
		p, _, err := prepareToken(ctx, c, a, s, in)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		record, sendErr := RunTokenAction(ctx, c, in, true, p.Digest, env)
		err = sendErr
		if err == nil && record != nil && record.State != "finalized" && record.State != "delivered" {
			err = ErrOutcomeUnknown
		}
		if err != nil {
			failures = append(failures, fmt.Errorf("pause %s: %w", a.AssetID, err))
		}
	}
	return errors.Join(failures...)
}

func tokenAdmissionClear(c NodeConfig, s TokenSession, assetID string) error {
	if pause, err := ReadAdmissionPause(c.StateDir); err != nil || pause != nil {
		return errors.New("local admission pause holds token offers")
	}
	return tokenAlarmClear(c, s, assetID)
}
func tokenAlarmClear(c NodeConfig, s TokenSession, assetID string) error {
	alerts, err := readTokenMonitor(c, s.Checkpoint(), s.ChainTime().Unix())
	if err != nil {
		return err
	}
	if alerts[assetID] {
		return errors.New("asset alarm holds token admission")
	}
	return nil
}
