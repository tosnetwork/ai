package toschain

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// FinalizedAccount is an account's state and balance at a session
// checkpoint. Its code is not checked: it is read for a wallet the caller
// funds and activates, whose contract is the caller's own.
type FinalizedAccount struct {
	// State is the node's account state: active, uninitialized or frozen.
	State       string
	BalanceNano uint64
}

// Active reports whether the account runs its code.
func (a FinalizedAccount) Active() bool { return a.State == "active" }

// Account reads a workchain 0 account's state and balance at the session
// checkpoint by quorum. A never-funded account is uninitialized with
// balance zero.
func (s *ServiceActorSession) Account(ctx context.Context, account string) (FinalizedAccount, error) {
	canonical, err := CanonicalAddress(account)
	if err != nil || !strings.HasPrefix(canonical, "0:") {
		return FinalizedAccount{}, errors.New("an account is a raw workchain 0 address")
	}
	type vote struct {
		State   string `json:"state"`
		Balance uint64 `json:"balance"`
		Root    string `json:"root"`
		File    string `json:"file"`
	}
	value, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (vote, error) {
		var info accountInformation
		if err := node.client.Call(ctx, "getAddressInformation", struct {
			Address string `json:"address"`
			Seqno   uint64 `json:"seqno"`
		}{canonical, s.seqno}, &info); err != nil {
			return vote{}, err
		}
		if info.BlockID.Type != "tos.blockIdExt" || info.BlockID.Workchain != -1 || info.BlockID.Seqno != s.seqno {
			return vote{}, errors.New("the account response is not at the session checkpoint")
		}
		root, file, err := blockHashes(info.BlockID)
		if err != nil {
			return vote{}, err
		}
		switch info.State {
		case "active", "uninitialized", "frozen":
		default:
			return vote{}, fmt.Errorf("unknown account state %q", info.State)
		}
		balance, err := strconv.ParseUint(info.Balance, 10, 64)
		if err != nil || strconv.FormatUint(balance, 10) != info.Balance {
			return vote{}, errors.New("the account balance is not a canonical decimal")
		}
		return vote{State: info.State, Balance: balance, Root: root, File: file}, nil
	})
	if err != nil {
		return FinalizedAccount{}, err
	}
	if err := s.pinHashes(value.Root, value.File); err != nil {
		return FinalizedAccount{}, err
	}
	return FinalizedAccount{State: value.State, BalanceNano: value.Balance}, nil
}
