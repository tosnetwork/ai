package toschain

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/tosnetwork/tosutils-go/tlb"
)

// WalletOutMessage is one internal out-message of a wallet transaction.
type WalletOutMessage struct {
	Destination string `json:"destination"`
	// QueryID is the body's query_id (after a 32-bit opcode); Known is false
	// when the body is shorter than that.
	QueryID uint64 `json:"query_id"`
	Known   bool   `json:"known"`
}

// WalletTransaction is one finalized wallet transaction, reduced to what a
// sender needs to tell which of its external messages it consumed.
type WalletTransaction struct {
	LT   uint64 `json:"lt"`
	Hash string `json:"hash"`
	Now  uint32 `json:"now"`
	// ExternalMessageHash is the lowercase hex hash of the inbound external
	// message cell; empty when the inbound message is not external.
	ExternalMessageHash string             `json:"external_message_hash,omitempty"`
	Out                 []WalletOutMessage `json:"out,omitempty"`
}

// WalletHistory is a wallet's finalized history since an anchor, newest
// first.
type WalletHistory struct {
	Head         ActorTxID           `json:"head"`
	Transactions []WalletTransaction `json:"transactions"`
	BlockRoot    string              `json:"block_root"`
	BlockFile    string              `json:"block_file"`
}

// WalletLastTransaction reads a wallet's last transaction at the session
// checkpoint. A sender records it before sending, as the anchor of the
// history it later reads.
func (s *ServiceActorSession) WalletLastTransaction(ctx context.Context, wallet string) (ActorTxID, error) {
	canonical, err := CanonicalAddress(wallet)
	if err != nil {
		return ActorTxID{}, err
	}
	type vote struct {
		Last      ActorTxID `json:"last"`
		BlockRoot string    `json:"block_root"`
		BlockFile string    `json:"block_file"`
	}
	value, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (vote, error) {
		last, root, file, err := finalizedActorLastTransaction(ctx, node, canonical, s.seqno)
		if err != nil {
			return vote{}, err
		}
		id, err := txIDOf(last)
		if err != nil {
			return vote{}, err
		}
		return vote{Last: id, BlockRoot: root, BlockFile: file}, nil
	})
	if err != nil {
		return ActorTxID{}, err
	}
	if err := s.pinHashes(value.BlockRoot, value.BlockFile); err != nil {
		return ActorTxID{}, err
	}
	return value.Last, nil
}

// WalletHistory walks a wallet's finalized transactions from its last
// transaction at the session checkpoint back to anchor (exclusive). The
// anchor must be in the history: a walk that does not meet it, or exceeds
// the reader's bound, is refused rather than returned partial.
func (s *ServiceActorSession) WalletHistory(ctx context.Context, wallet string, anchor ActorTxID) (*WalletHistory, error) {
	canonical, err := CanonicalAddress(wallet)
	if err != nil {
		return nil, err
	}
	if anchor.LT == 0 || anchor.Hash == "" {
		return nil, errors.New("a wallet history needs an anchor transaction")
	}
	type vote struct {
		History WalletHistory `json:"history"`
		Result  HistoryResult `json:"result"`
	}
	value, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (vote, error) {
		last, root, file, err := finalizedActorLastTransaction(ctx, node, canonical, s.seqno)
		if err != nil {
			return vote{}, err
		}
		raw, _, err := walkActorHistory(ctx, node, canonical, last, &anchor, s.reader.maxHistory)
		switch {
		case errors.Is(err, ErrHistoryAnchorMissing):
			return vote{Result: historyAnchorMissing, History: WalletHistory{BlockRoot: root, BlockFile: file}}, nil
		case errors.Is(err, ErrHistoryBoundExceeded):
			return vote{Result: historyBoundExceeded, History: WalletHistory{BlockRoot: root, BlockFile: file}}, nil
		case err != nil:
			return vote{}, err
		}
		transactions := make([]WalletTransaction, 0, len(raw))
		for _, transaction := range raw {
			reduced, err := reduceWalletTransaction(transaction)
			if err != nil {
				return vote{}, err
			}
			transactions = append(transactions, reduced)
		}
		head := anchor
		if len(transactions) > 0 {
			head = ActorTxID{LT: transactions[0].LT, Hash: transactions[0].Hash}
		}
		return vote{Result: HistoryAnchorReached, History: WalletHistory{Head: head, Transactions: transactions,
			BlockRoot: root, BlockFile: file}}, nil
	})
	if err != nil {
		return nil, err
	}
	if err := s.pinHashes(value.History.BlockRoot, value.History.BlockFile); err != nil {
		return nil, err
	}
	switch value.Result {
	case historyAnchorMissing:
		return nil, ErrHistoryAnchorMissing
	case historyBoundExceeded:
		return nil, ErrHistoryBoundExceeded
	}
	return &value.History, nil
}

func txIDOf(id transactionID) (ActorTxID, error) {
	lt, err := strconv.ParseUint(id.LT, 10, 64)
	if err != nil {
		return ActorTxID{}, errors.New("invalid transaction logical time")
	}
	hash, err := decodeBase64Hash(id.Hash)
	if err != nil {
		return ActorTxID{}, err
	}
	return ActorTxID{LT: lt, Hash: hex.EncodeToString(hash)}, nil
}

// reduceWalletTransaction keeps the inbound external message hash and the
// internal out-messages' destinations and query IDs.
func reduceWalletTransaction(transaction tlb.Transaction) (WalletTransaction, error) {
	reduced := WalletTransaction{LT: transaction.LT, Hash: hex.EncodeToString(transaction.Hash), Now: transaction.Now}
	if transaction.IO.In != nil && transaction.IO.In.MsgType == tlb.MsgTypeExternalIn {
		message, err := transaction.IO.In.ToCell()
		if err != nil {
			return WalletTransaction{}, errors.New("wallet inbound external message does not serialize")
		}
		reduced.ExternalMessageHash = hex.EncodeToString(message.Hash())
	}
	if transaction.IO.Out == nil {
		return reduced, nil
	}
	messages, err := transaction.IO.Out.ToSlice()
	if err != nil || len(messages) != int(transaction.OutMsgCount) {
		return WalletTransaction{}, errors.New("invalid wallet out-message list")
	}
	for _, message := range messages {
		if message.MsgType != tlb.MsgTypeInternal {
			continue
		}
		out := message.AsInternal()
		destination, err := addressText(out.DstAddr)
		if err != nil {
			return WalletTransaction{}, errors.New("wallet out-message destination does not decode")
		}
		entry := WalletOutMessage{Destination: destination}
		if out.Body != nil {
			if body, err := out.Body.BeginParse(); err == nil {
				if _, err := body.LoadUInt(32); err == nil {
					if query, err := body.LoadUInt(64); err == nil {
						entry.QueryID, entry.Known = query, true
					}
				}
			}
		}
		reduced.Out = append(reduced.Out, entry)
	}
	return reduced, nil
}
