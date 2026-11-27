package buyersdk

import (
	"math/big"
	"strings"
	"testing"

	"github.com/tosnetwork/ai/protocol/pkg/tokenissuer"
)

func TestTokenLockBudgetUsesMintedAmount(t *testing.T) {
	snapshot := tokenissuer.Snapshot{FeeBasisPoints: 19, MaximumFee: "1000000"}
	master, actor := "0:"+strings.Repeat("11", 32), "0:"+strings.Repeat("22", 32)
	limit := TokenAssetLimits{MaxPerCallAtomic: big.NewInt(99810000), MaxWindowAtomic: big.NewInt(199620000)}
	p, err := previewTokenLockAt(snapshot, master, actor, big.NewInt(100000000), big.NewInt(100000000), big.NewInt(99810000), limit)
	if err != nil {
		t.Fatal(err)
	}
	if p.MintedAtomic != "99810000" || p.BudgetDebitAtomic != p.MintedAtomic || p.NominalAtomic != "100000000" || p.IssuerFeeAtomic != "190000" || !strings.Contains(p.Warning, "refused and returned") {
		t.Fatalf("preview: %+v", p)
	}
	if _, err = previewTokenLockAt(snapshot, master, actor, big.NewInt(100000000), big.NewInt(100000000), big.NewInt(99810001), limit); err == nil {
		t.Fatal("window budget ignored")
	}
	limit.MaxPerCallAtomic = big.NewInt(99809999)
	if _, err = previewTokenLockAt(snapshot, master, actor, big.NewInt(100000000), big.NewInt(100000000), new(big.Int), limit); err == nil {
		t.Fatal("per-call budget ignored")
	}
}
func TestNoIssuerFeeIsAppliedTwiceToActorFunding(t *testing.T) {
	snapshot := tokenissuer.Snapshot{FeeBasisPoints: 0, MaximumFee: "0"}
	price := big.NewInt(100000000)
	limit := TokenAssetLimits{MaxPerCallAtomic: price, MaxWindowAtomic: price}
	p, err := previewTokenLockAt(snapshot, "0:"+strings.Repeat("11", 32), "0:"+strings.Repeat("22", 32), price, price, new(big.Int), limit)
	if err != nil || p.MintedAtomic != price.String() || p.ActorPriceAtomic != price.String() || p.Warning != "" {
		t.Fatalf("zero fee: %+v %v", p, err)
	}
}
