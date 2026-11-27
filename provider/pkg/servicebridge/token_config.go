package servicebridge

import (
	"encoding/hex"
	"errors"
	"math/big"
	"path/filepath"
	"regexp"

	"github.com/tosnetwork/ai/protocol/pkg/agentsocket"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// TokenProviderConfig is operator policy, not supplied by a model or monitor.
type TokenProviderConfig struct {
	Pins                []toschain.TokenAssetPin `json:"pins"`
	Actors              []TokenActorConfig       `json:"actors"`
	MonitorReport       string                   `json:"monitor_report"`
	MaxReportAgeSeconds uint32                   `json:"max_report_age_seconds,omitempty"`
}
type TokenActorConfig struct {
	Address                 string `json:"address"`
	CodeHash                string `json:"code_hash"`
	AssetID                 string `json:"asset_id"`
	Master                  string `json:"master"`
	CapabilityID            string `json:"capability_id"`
	Version                 string `json:"version"`
	ManifestFile            string `json:"manifest_file"`
	MinPriceAtomic          string `json:"min_price_atomic"`
	MaxPriceAtomic          string `json:"max_price_atomic"`
	MaxLiabilityAtomic      string `json:"max_liability_atomic"`
	MaxStorageFeeNanoTOS    string `json:"max_storage_fee_nanotos"`
	MaxCleanupBountyNanoTOS string `json:"max_cleanup_bounty_nanotos"`
	MinActorFreeNanoTOS     string `json:"min_actor_free_nanotos"`
	MinWalletNanoTOS        string `json:"min_wallet_nanotos"`
}

var capabilityIDPattern = regexp.MustCompile(`^cap_[0-9a-f]{64}$`)
var tokenLabel = regexp.MustCompile(`^[a-zA-Z0-9_.:/-]{1,160}$`)

func tokenUnits(text string, positive bool) (*big.Int, error) {
	if len(text) == 0 || len(text) > 37 || len(text) > 1 && text[0] == '0' {
		return nil, errors.New("invalid atomic amount")
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			return nil, errors.New("invalid atomic amount")
		}
	}
	n, ok := new(big.Int).SetString(text, 10)
	if !ok || n.Sign() < 0 || positive && n.Sign() == 0 || n.Cmp(nativecore.MaxServiceActorCoins) >= 0 {
		return nil, errors.New("atomic amount outside Coins range")
	}
	return n, nil
}
func (c TokenProviderConfig) Validate() error {
	if len(c.Actors) == 0 || len(c.Actors) > 64 || len(c.Pins) == 0 || len(c.Pins) > toschain.MaxPinnedTokenAssets || !cleanAbsolute(c.MonitorReport) || c.MaxReportAgeSeconds > 3600 {
		return errors.New("invalid token provider configuration bounds")
	}
	seen := map[string]bool{}
	labels := map[string]string{}
	masters := map[string]string{}
	for _, a := range c.Actors {
		if canonical, err := toschain.CanonicalAddress(a.Address); err != nil || canonical != a.Address || !rawAddressPattern.MatchString(a.Address) || a.Address[:2] != "0:" {
			return errors.New("token actor must be canonical on workchain zero")
		}
		if seen[a.Address] {
			return errors.New("duplicate token actor")
		}
		seen[a.Address] = true
		if !tokenLabel.MatchString(a.AssetID) || !cleanAbsolute(a.ManifestFile) || !validVersion(a.Version) || !capabilityIDPattern.MatchString(a.CapabilityID) {
			return errors.New("invalid token offer identity")
		}
		if master, ok := labels[a.AssetID]; ok && master != a.Master {
			return errors.New("asset label maps to different masters")
		}
		labels[a.AssetID] = a.Master
		if label, exists := masters[a.Master]; exists && label != a.AssetID {
			return errors.New("one master has multiple alarm labels")
		}
		masters[a.Master] = a.AssetID
		if a.CodeHash != "tvm-cell-sha256:"+hex.EncodeToString(nativecore.ServiceActorTokenReleaseCodeHash[:]) && a.CodeHash != "tvm-cell-sha256:"+hex.EncodeToString(nativecore.ServiceActorTokenTestProfileCodeHash[:]) {
			return errors.New("unsupported token actor release")
		}
		min, err := tokenUnits(a.MinPriceAtomic, true)
		if err != nil {
			return err
		}
		max, err := tokenUnits(a.MaxPriceAtomic, true)
		if err != nil || min.Cmp(max) > 0 {
			return errors.New("invalid token price bounds")
		}
		for _, v := range []string{a.MaxLiabilityAtomic, a.MaxStorageFeeNanoTOS, a.MaxCleanupBountyNanoTOS, a.MinActorFreeNanoTOS, a.MinWalletNanoTOS} {
			if _, err = tokenUnits(v, true); err != nil {
				return err
			}
		}
		matched := 0
		for _, p := range c.Pins {
			if p.Master == a.Master {
				matched++
			}
		}
		if matched != 1 {
			return errors.New("token actor needs exactly one independent asset pin")
		}
	}
	return nil
}
func (c TokenProviderConfig) Actor(address string) (TokenActorConfig, error) {
	if err := c.Validate(); err != nil {
		return TokenActorConfig{}, err
	}
	for _, a := range c.Actors {
		if a.Address == address {
			return a, nil
		}
	}
	return TokenActorConfig{}, errors.New("actor not in operator configuration")
}
func tokenStateDir(config NodeConfig, actor string) string {
	return filepath.Join(config.StateDir, "token", actor[2:])
}

// ReadTokenActionInput uses the same private-file boundary as custody configuration.
func ReadTokenActionInput(path string) (TokenActionInput, error) {
	var in TokenActionInput
	if !cleanAbsolute(path) {
		return in, errors.New("token input path must be absolute and clean")
	}
	raw, err := readPrivateFile(path, 64<<10)
	if err != nil {
		return in, err
	}
	if err := agentsocket.DecodeParams(raw, &in); err != nil {
		return in, err
	}
	return in, checkTokenInput(in)
}
