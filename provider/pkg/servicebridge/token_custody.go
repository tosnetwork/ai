package servicebridge

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/tosnetwork/ai/protocol/pkg/toschain"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type TokenNonDelivery struct {
	State       string `json:"state"`
	Checkpoint  uint64 `json:"checkpoint"`
	BlockRoot   string `json:"block_root"`
	BlockFile   string `json:"block_file"`
	ChainTime   int64  `json:"chain_time"`
	WalletSeqno uint32 `json:"wallet_seqno"`
}
type TokenDelivery struct {
	Proof        *TokenNonDelivery  `json:"non_delivery,omitempty"`
	Seqno        uint32             `json:"seqno"`
	ValidUntil   uint32             `json:"valid_until"`
	MessageHash  string             `json:"message_hash"`
	WalletAnchor toschain.ActorTxID `json:"wallet_anchor"`
	// The BOC stays in custody memory, never in client projections.
	MessageBOC string `json:"-"`
}

// The application supplies the network pins, exact-envelope checks and durable
// custody journal that the low-level exact-message broadcaster does not supply.
func prepareTokenDelivery(ctx context.Context, c NodeConfig, s TokenSession, record *TokenActionRecord, runner TOSCTLRunner, env TokenEnv) (*TokenDelivery, error) {
	if err := env.CheckCustody(ctx, c, s); err != nil {
		return nil, err
	}
	wallet, err := (tosctlOps{runner: runner}).wallet(ctx, c.WalletName)
	if err != nil {
		return nil, err
	}
	if wallet.Address != c.WalletAddress {
		return nil, errors.New("custody wallet identity changed")
	}
	if err := requireExpiringWallet(wallet); err != nil {
		return nil, err
	}
	seq, err := s.WalletSeqno(ctx, c.WalletAddress)
	if err != nil {
		return nil, err
	}
	anchor, err := s.WalletLastTransaction(ctx, c.WalletAddress)
	if err != nil {
		return nil, err
	}
	if anchor.LT == 0 || !hex64Pattern.MatchString(anchor.Hash) {
		return nil, errors.New("custody wallet anchor unavailable")
	}
	global, err := s.ReadTokenGlobalID(ctx)
	if err != nil {
		return nil, err
	}
	m := record.Preview.Message
	value, err := tokenUnits(m.ValueNanotos, false)
	if err != nil || !value.IsUint64() || !m.Bounce {
		return nil, errors.New("invalid token envelope value or bounce")
	}
	var out struct {
		Version       string `json:"version"`
		ValidUntil    uint32 `json:"valid_until"`
		Wallet        string `json:"wallet"`
		Payer         string `json:"payer"`
		Destination   string `json:"destination"`
		Amount        uint64 `json:"amount_nanotos"`
		BodyHash      string `json:"body_hash"`
		StateInitHash string `json:"state_init_hash"`
		BOC           string `json:"message_boc_base64"`
	}
	err = runTOSCTLJSON(ctx, runner, TOSCTLCall{Label: "wallet build token", Args: []string{"wallet", "send", "--from", c.WalletName, "--to", m.Destination, "--amount-nanotos", value.String(), "--body-boc", m.BodyBOC, "--bounce", "--build-only"}, MaxOutput: maxTOSCTLJSONOutput}, false, &out)
	if err != nil {
		return nil, err
	}
	if out.Version != "tosctl.wallet-prepared-send.v2" || out.ValidUntil == 0 || out.Wallet != c.WalletName || !sameTokenAddress(out.Payer, c.WalletAddress) || !sameTokenAddress(out.Destination, m.Destination) || out.Amount != value.Uint64() || out.BodyHash != "tvm-cell-sha256:"+record.BodyHash || out.StateInitHash != "" {
		return nil, errors.New("custody prepared another token envelope")
	}
	root, err := decodeCellBOCText(out.BOC)
	if err != nil {
		return nil, err
	}
	expiry, err := checkTokenWalletMessage(root, wallet.Type, global, seq, c.WalletAddress, m.Destination, value.Uint64(), record.BodyHash)
	if err != nil {
		return nil, err
	}
	if out.ValidUntil != expiry {
		return nil, errors.New("custody expiry differs from the signed token message")
	}
	now := env.Now().Unix()
	if now < 0 || int64(expiry) <= now || int64(expiry) > now+600 || int64(expiry) <= s.ChainTime().Unix() {
		return nil, errors.New("custody message expiry outside the signing window")
	}
	return &TokenDelivery{Seqno: seq, ValidUntil: expiry, MessageHash: hex.EncodeToString(root.Hash()), MessageBOC: out.BOC, WalletAnchor: anchor}, nil
}
func sameTokenAddress(a, b string) bool {
	canonical, err := rawWalletAddress(a)
	return err == nil && canonical == b
}

func checkTokenWalletMessage(root *cell.Cell, kind string, global int32, seq uint32, wallet, dest string, value uint64, bodyHash string) (uint32, error) {
	if root == nil || root.IsSpecial() {
		return 0, errors.New("invalid wallet message cell")
	}
	var ext tlb.ExternalMessage
	s, err := root.BeginParse()
	if err != nil {
		return 0, err
	}
	if err := tlb.LoadFromCell(&ext, s); err != nil {
		return 0, err
	}
	if s.BitsLeft() != 0 || s.RefsNum() != 0 || ext.StateInit != nil || ext.DstAddr == nil || ext.DstAddr.StringRaw() != wallet || ext.Body == nil {
		return 0, errors.New("invalid external wallet envelope")
	}
	b, err := ext.Body.BeginParse()
	if err != nil {
		return 0, err
	}
	if kind == "V5R1" {
		prefix, e := b.LoadUInt(32)
		if e != nil || prefix != 0x7369676e {
			return 0, errors.New("invalid signed wallet prefix")
		}
	} else {
		if _, err = b.LoadSlice(512); err != nil {
			return 0, err
		}
	}
	gid, err := b.LoadInt(32)
	if err != nil || gid != int64(global) {
		return 0, errors.New("wallet message global id mismatch")
	}
	if _, err = b.LoadUInt(32); err != nil {
		return 0, err
	}
	until, err := b.LoadUInt(32)
	if err != nil {
		return 0, err
	}
	signedSeq, err := b.LoadUInt(32)
	if err != nil || signedSeq != uint64(seq) {
		return 0, errors.New("wallet message seqno differs from finalized state")
	}
	if kind == "V4R2" {
		op, e := b.LoadUInt(8)
		if e != nil || op != 0 {
			return 0, errors.New("wallet message is not a simple transfer")
		}
	}
	var msg *cell.Cell
	if kind == "V5R1" {
		yes, e := b.LoadBoolBit()
		if e != nil || !yes {
			return 0, errors.New("missing wallet actions")
		}
		actions, e := b.LoadRef()
		if e != nil {
			return 0, e
		}
		other, e := b.LoadBoolBit()
		if e != nil || other {
			return 0, errors.New("unexpected wallet actions")
		}
		if _, e = b.LoadSlice(512); e != nil {
			return 0, e
		}
		var list tlb.OutList
		if e = tlb.LoadFromCell(&list, actions); e != nil {
			return 0, e
		}
		action, ok := list.Out.(tlb.ActionSendMsg)
		if !ok || action.Mode != 3 || list.Prev == nil || list.Prev.BitsSize() != 0 || list.Prev.RefsNum() != 0 || actions.BitsLeft() != 0 || actions.RefsNum() != 0 {
			return 0, errors.New("wallet action list is not one send")
		}
		msg = action.Msg
	} else {
		mode, e := b.LoadUInt(8)
		if e != nil || mode != 3 {
			return 0, errors.New("wallet send mode mismatch")
		}
		ref, e := b.LoadRef()
		if e != nil {
			return 0, e
		}
		msg, err = ref.ToCell()
		if err != nil {
			return 0, err
		}
	}
	if b.BitsLeft() != 0 || b.RefsNum() != 0 {
		return 0, errors.New("wallet message has extra effects")
	}
	var inner tlb.InternalMessage
	if msg == nil {
		return 0, errors.New("missing wallet transfer")
	}
	innerSlice, e := msg.BeginParse()
	if e != nil {
		return 0, e
	}
	if err = tlb.LoadFromCell(&inner, innerSlice); err != nil {
		return 0, err
	}
	extra, err := inner.ExtraCurrencies.LoadAll()
	if err != nil {
		return 0, err
	}
	if len(extra) != 0 || inner.StateInit != nil || inner.DstAddr == nil || inner.DstAddr.StringRaw() != dest || !inner.Bounce || inner.Bounced || inner.Amount.Nano().Cmp(new(big.Int).SetUint64(value)) != 0 || inner.Body == nil || hex.EncodeToString(inner.Body.Hash()) != bodyHash {
		return 0, errors.New("signed wallet transfer differs from confirmed token envelope")
	}
	return uint32(until), nil
}

func tokenDeliveryMissing(ctx context.Context, s TokenSession, c NodeConfig, r *TokenActionRecord) error {
	if r.State == "building" || r.State == "signed" || r.State == "never_sent" {
		r.State = "never_sent"
		return nil
	}
	d := r.Delivery
	if d == nil {
		r.State = "unknown"
		return nil
	}
	seq, err := s.WalletSeqno(ctx, c.WalletAddress)
	if err != nil {
		return err
	}
	if seq < d.Seqno {
		return errors.New("wallet sequence regressed")
	}
	if seq == d.Seqno && s.ChainTime().Unix() > int64(d.ValidUntil) {
		r.State = "expired"
		recordTokenNonDelivery(s, r, seq)
		r.Failure = "wallet message expired with unchanged finalized seqno"
		return nil
	}
	if seq > d.Seqno {
		history, err := s.WalletHistory(ctx, c.WalletAddress, d.WalletAnchor)
		if err != nil {
			return err
		}
		if history == nil {
			return errors.New("wallet history unavailable")
		}
		// A peer can rewrap an external without changing its signed body.
		// Match emitted effects across the whole anchored suffix before treating
		// any external hash or failed attempt as proof of non-delivery.
		for _, tx := range history.Transactions {
			for _, out := range tx.Out {
				if out.Known && out.QueryID == r.QueryID && out.Destination == r.Input.Actor {
					r.State = "unknown"
					return nil
				}
			}
		}
		for _, tx := range history.Transactions {
			if tx.ExternalMessageHash != d.MessageHash {
				continue
			}
			r.State = "never_sent"
			recordTokenNonDelivery(s, r, seq)
			r.Failure = "finalized wallet execution emitted no token action"
			return nil
		}
		r.State = "never_sent"
		recordTokenNonDelivery(s, r, seq)
		r.Failure = "wallet sequence consumed by another finalized message"
		return nil
	}
	r.State = "unknown"
	return nil
}
func broadcastTokenDelivery(ctx context.Context, runner TOSCTLRunner, d *TokenDelivery) error {
	if d == nil || d.MessageBOC == "" {
		return errors.New("missing prepared token message")
	}
	_, err := runner.Run(ctx, TOSCTLCall{Label: "wallet broadcast token", Args: []string{"wallet", "broadcast-prepared", "--message-boc", d.MessageBOC, "--yes", "--acknowledge-unpinned-manual-broadcast"}})
	return err
}

func recordTokenNonDelivery(s TokenSession, r *TokenActionRecord, seq uint32) {
	root, file := s.BlockHashes()
	r.Delivery.Proof = &TokenNonDelivery{State: r.State, Checkpoint: s.Checkpoint(), BlockRoot: root, BlockFile: file, ChainTime: s.ChainTime().Unix(), WalletSeqno: seq}
}
