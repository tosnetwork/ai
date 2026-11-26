package toschain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// TokenActorNotification is the wallet-authenticated funding envelope. A
// malformed payload remains observable on a refused funding; it never becomes
// an admitted call merely because the notification transaction succeeded.
type TokenActorNotification struct {
	QueryID           uint64                         `json:"query_id"`
	AmountAtomic      string                         `json:"amount_atomic"`
	From              string                         `json:"from"`
	ForwardPayloadBOC string                         `json:"forward_payload_boc"`
	Payload           *nativecore.TokenCallPayloadV1 `json:"payload,omitempty"`
}

// TokenActorOutput retains exact stored message hashes for funding-chain and
// report linkage. Body hashes are not substitutes for full message hashes.
type TokenActorOutput struct {
	Hash         string `json:"hash"`
	Destination  string `json:"destination"`
	ValueNano    string `json:"value_nanotos"`
	Bounce       bool   `json:"bounce"`
	Bounced      bool   `json:"bounced"`
	HasStateInit bool   `json:"has_state_init"`
	BodyBOC      string `json:"body_boc"`
}

// TokenActorTransaction is derived from a hash-checked transaction BOC.
type TokenActorTransaction struct {
	LT                 uint64                              `json:"lt"`
	Hash               string                              `json:"hash"`
	Now                uint32                              `json:"now"`
	Kind               string                              `json:"kind"`
	Sender             string                              `json:"sender,omitempty"`
	ValueNano          string                              `json:"value_nanotos,omitempty"`
	ExitCode           int32                               `json:"exit_code"`
	Bounced            bool                                `json:"bounced"`
	TookEffect         bool                                `json:"took_effect"`
	InboundMessageHash string                              `json:"inbound_message_hash,omitempty"`
	BodyBOC            string                              `json:"body_boc,omitempty"`
	Opcode             uint32                              `json:"opcode,omitempty"`
	QueryID            uint64                              `json:"query_id,omitempty"`
	RequestID          uint64                              `json:"request_id,omitempty"`
	ResponseHash       string                              `json:"response_hash,omitempty"`
	Signed             bool                                `json:"signed,omitempty"`
	Destination        string                              `json:"destination,omitempty"`
	Notification       *TokenActorNotification             `json:"notification,omitempty"`
	Logs               []nativecore.ServiceActorTokenLogV1 `json:"logs,omitempty"`
	LogBodyBOCs        []string                            `json:"log_body_bocs,omitempty"`
	Outputs            []TokenActorOutput                  `json:"outputs,omitempty"`
}

// DecodeTokenActorTransaction computes the transaction and message hashes
// from their exact cells, rather than trusting RPC summaries or re-encoding.
func DecodeTokenActorTransaction(actor string, boc []byte) (TokenActorTransaction, error) {
	root, err := cell.FromBOC(boc)
	if err != nil {
		return TokenActorTransaction{}, err
	}
	parse, err := tokenOrdinary(root)
	if err != nil {
		return TokenActorTransaction{}, err
	}
	var tx tlb.Transaction
	if err = tlb.LoadFromCell(&tx, parse); err != nil {
		return TokenActorTransaction{}, err
	}
	if err = tokenExhausted(parse); err != nil {
		return TokenActorTransaction{}, err
	}
	tx.Hash = root.Hash()
	return classifyTokenActorTransaction(actor, tx, root)
}

func classifyTokenActorTransaction(actor string, tx tlb.Transaction, root *cell.Cell) (TokenActorTransaction, error) {
	result := TokenActorTransaction{LT: tx.LT, Hash: hex.EncodeToString(tx.Hash), Now: tx.Now}
	canonical, err := CanonicalAddress(actor)
	if err != nil || canonical != actor || !strings.HasPrefix(actor, "0:") {
		return result, errors.New("invalid token actor address")
	}
	account, err := hex.DecodeString(strings.TrimPrefix(actor, "0:"))
	if err != nil || !bytes.Equal(tx.AccountAddr, account) {
		return result, errors.New("token history contains another account")
	}
	ordinary, ok := tx.Description.(tlb.TransactionDescriptionOrdinary)
	if !ok {
		result.Kind = ActorTxSystem
		return result, nil
	}
	if vm, ok := ordinary.ComputePhase.Phase.(tlb.ComputePhaseVM); ok {
		result.TookEffect = vm.Success && !ordinary.Aborted
		result.ExitCode = vm.Details.ExitCode
	}
	if tx.IO.In == nil {
		result.Kind = ActorTxNoInput
		return result, nil
	}
	inCell, err := storedInboundMessage(root)
	if err != nil {
		return result, err
	}
	result.InboundMessageHash = hex.EncodeToString(inCell.Hash())
	if tx.IO.In.MsgType != tlb.MsgTypeInternal {
		result.Kind = ActorTxExternal
		return result, nil
	}
	in := tx.IO.In.AsInternal()
	result.Sender, err = addressText(in.SrcAddr)
	if err != nil {
		return result, err
	}
	result.ValueNano = in.Amount.Nano().String()
	body := in.Body
	if body == nil {
		body = cell.BeginCell().EndCell()
	}
	result.BodyBOC = bocText(body)
	result.Bounced = in.Bounced
	if !result.TookEffect {
		result.Kind = ActorTxFailed
		return result, nil
	}
	result.Outputs, result.Logs, result.LogBodyBOCs, err = tokenActorOutputs(actor, tx, root)
	if err != nil {
		return result, err
	}
	if in.Bounced {
		result.Kind = ActorTxBounced
		if p, err := body.BeginParse(); err == nil {
			if prefix, err := p.LoadUInt(32); err == nil && prefix == 0xffffffff {
				if op, err := p.LoadUInt(32); err == nil {
					result.Opcode = uint32(op)
					result.QueryID, _ = p.LoadUInt(64)
				}
			}
		}
		return result, nil
	}
	if body.BitsSize() == 0 && body.RefsNum() == 0 {
		result.Kind = ActorTxTransfer
		return result, nil
	}
	parsed, err := body.BeginParse()
	if err != nil {
		return result, err
	}
	op, err := parsed.LoadUInt(32)
	if err != nil {
		return result, errors.New("successful token actor message has no opcode")
	}
	result.Opcode = uint32(op)
	query, err := parsed.LoadUInt(64)
	if err != nil {
		return result, errors.New("successful token actor message has no query id")
	}
	result.QueryID = query
	result.Kind = ActorTxOwner
	switch result.Opcode {
	case 0x7362d09c:
		result.Kind = "notification"
		// Notification inputs follow VM Coins semantics; a foreign sender may
		// use a non-minimal form without changing actor state. Logs are canonical.
		amount, err := parsed.LoadBigCoins()
		if err != nil {
			return result, err
		}
		sender, err := parsed.LoadAddr()
		if err != nil {
			return result, err
		}
		from, err := tokenHistoryAddress(sender)
		if err != nil {
			return result, err
		}
		payload, err := parsed.ToCell()
		if err != nil {
			return result, err
		}
		n := &TokenActorNotification{QueryID: query, AmountAtomic: amount.String(), From: from, ForwardPayloadBOC: bocText(payload)}
		if decoded, err := nativecore.DecodeServiceActorTokenForwardPayload(payload); err == nil {
			n.Payload = &decoded
		}
		result.Notification = n
		snapshots, fundings := 0, 0
		for _, log := range result.Logs {
			if log.Snapshot != nil {
				snapshots++
			}
			if log.Funding != nil {
				fundings++
			}
		}
		if snapshots > 1 || fundings > 1 || snapshots+fundings > 1 {
			return result, errors.New("funding emitted conflicting admission logs")
		}
		for _, log := range result.Logs {
			if log.Funding != nil && (log.Funding.QueryID != n.QueryID || log.Funding.Amount.String() != n.AmountAtomic || log.Funding.From.Text() != n.From) {
				return result, errors.New("funding refusal differs from its notification")
			}
			if log.Snapshot != nil && (n.Payload == nil || log.Snapshot.Caller.Text() != n.From || log.Snapshot.Terms.PricePerCall.String() != n.AmountAtomic || log.Snapshot.RequestHash != n.Payload.RequestHash || log.Snapshot.TermsHash != n.Payload.ExpectedTermsHash) {
				return result, errors.New("request snapshot differs from its notification")
			}
		}
		if snapshots == 1 {
			if n.Payload == nil {
				return result, errors.New("admitted funding has a malformed token_call")
			}
			result.Kind = ActorTxCall
		}
		if fundings == 1 {
			result.Kind = "funding_refused"
		}
	case nativecore.ServiceActorTokenRespondOpcode, nativecore.ServiceActorTokenExpireOpcode, nativecore.ServiceActorTokenClaimRefundOpcode, nativecore.ServiceActorTokenSweepOpcode, nativecore.ServiceActorTokenClaimReturnedOpcode, nativecore.ServiceActorTokenSweepReturnedOpcode, nativecore.ServiceActorTokenRecheckOpcode, nativecore.ServiceActorTokenAbandonOpcode:
		id, err := parsed.LoadUInt(64)
		if err != nil {
			return result, err
		}
		result.RequestID = id
		switch result.Opcode {
		case nativecore.ServiceActorTokenRespondOpcode:
			result.Kind = ActorTxRespond
			hash, err := parsed.LoadSlice(256)
			if err != nil {
				return result, err
			}
			result.ResponseHash = hex.EncodeToString(hash)
			result.Signed = parsed.RefsNum() > 0
		case nativecore.ServiceActorTokenExpireOpcode:
			result.Kind = ActorTxExpire
		case nativecore.ServiceActorTokenClaimRefundOpcode, nativecore.ServiceActorTokenClaimReturnedOpcode:
			result.Kind = ActorTxClaim
			destination, err := parsed.LoadAddr()
			if err != nil {
				return result, err
			}
			result.Destination, err = addressText(destination)
			if err != nil {
				return result, err
			}
		case nativecore.ServiceActorTokenSweepOpcode, nativecore.ServiceActorTokenSweepReturnedOpcode:
			result.Kind = ActorTxSweep
		}
	case 0xd53276db:
		result.Kind = ActorTxTransfer
	}
	return result, nil
}

func tokenActorOutputs(actor string, tx tlb.Transaction, root *cell.Cell) ([]TokenActorOutput, []nativecore.ServiceActorTokenLogV1, []string, error) {
	messages, err := tokenStoredOutMessages(root, tx.OutMsgCount)
	if err != nil {
		return nil, nil, nil, err
	}
	var outputs []TokenActorOutput
	var logs []nativecore.ServiceActorTokenLogV1
	var bodies []string
	for _, stored := range messages {
		decoded, message := stored.message, stored.root
		switch decoded.MsgType {
		case tlb.MsgTypeInternal:
			value := decoded.AsInternal()
			destination, err := addressText(value.DstAddr)
			if err != nil {
				return nil, nil, nil, err
			}
			body := value.Body
			if body == nil {
				body = cell.BeginCell().EndCell()
			}
			outputs = append(outputs, TokenActorOutput{Hash: hex.EncodeToString(message.Hash()), Destination: destination, ValueNano: value.Amount.Nano().String(), Bounce: value.Bounce, Bounced: value.Bounced, HasStateInit: value.StateInit != nil, BodyBOC: bocText(body)})
		case tlb.MsgTypeExternalOut:
			value := decoded.AsExternalOut()
			source, sourceErr := addressText(value.SrcAddr)
			if sourceErr != nil || source != actor || (value.DstAddr != nil && !value.DstAddr.IsAddrNone()) || value.StateInit != nil || value.Body == nil {
				return nil, nil, nil, errors.New("token actor log envelope is invalid")
			}
			log, err := nativecore.DecodeServiceActorTokenLog(value.Body)
			if err != nil {
				return nil, nil, nil, err
			}
			logs = append(logs, *log)
			bodies = append(bodies, bocText(value.Body))
		default:
			return nil, nil, nil, errors.New("unexpected token actor out-message type")
		}
	}
	return outputs, logs, bodies, nil
}

// TokenActorHistory is a complete or anchored exact-transaction history.
type TokenActorHistory struct {
	Result       HistoryResult           `json:"result"`
	Head         ActorTxID               `json:"head"`
	Transactions []TokenActorTransaction `json:"transactions"`
	BlockRoot    string                  `json:"block_root"`
	BlockFile    string                  `json:"block_file"`
}

func (s *ServiceActorSession) TokenHistory(ctx context.Context, actor string, anchor *ActorTxID) (*TokenActorHistory, error) {
	if s == nil || s.reader == nil {
		return nil, errors.New("token session is required")
	}
	canonical, err := CanonicalAddress(actor)
	if err != nil || canonical != actor || !strings.HasPrefix(actor, "0:") {
		return nil, errors.New("invalid token actor address")
	}
	history, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (TokenActorHistory, error) {
		if err := s.tokenVerifyEndpointNetwork(ctx, node); err != nil {
			return TokenActorHistory{}, err
		}
		last, root, file, err := finalizedActorLastTransaction(ctx, node, canonical, s.seqno)
		if err != nil {
			return TokenActorHistory{}, err
		}
		raw, result, err := walkHistoryEntries(ctx, node, canonical, last, anchor, s.reader.maxHistory)
		switch {
		case errors.Is(err, ErrHistoryAnchorMissing):
			return TokenActorHistory{Result: historyAnchorMissing, BlockRoot: root, BlockFile: file}, nil
		case errors.Is(err, ErrHistoryBoundExceeded):
			return TokenActorHistory{Result: historyBoundExceeded, BlockRoot: root, BlockFile: file}, nil
		case err != nil:
			return TokenActorHistory{}, err
		}
		transactions := make([]TokenActorTransaction, 0, len(raw))
		for _, entry := range raw {
			if !s.chainTime.IsZero() && int64(entry.transaction.Now) > s.chainTime.Unix() {
				return TokenActorHistory{}, errors.New("token transaction is newer than its checkpoint")
			}
			tx, err := classifyTokenActorTransaction(canonical, entry.transaction, entry.root)
			if err != nil {
				return TokenActorHistory{}, err
			}
			transactions = append(transactions, tx)
		}
		head := ActorTxID{}
		if len(transactions) > 0 {
			head = ActorTxID{LT: transactions[0].LT, Hash: transactions[0].Hash}
		} else if anchor != nil {
			head = *anchor
		}
		return TokenActorHistory{Result: result, Head: head, Transactions: transactions, BlockRoot: root, BlockFile: file}, nil
	})
	if err != nil {
		return nil, err
	}
	if err = s.pinHashes(history.BlockRoot, history.BlockFile); err != nil {
		return nil, err
	}
	if history.Result == historyAnchorMissing {
		return nil, ErrHistoryAnchorMissing
	}
	if history.Result == historyBoundExceeded {
		return nil, ErrHistoryBoundExceeded
	}
	return &history, nil
}

// TokenHistoricalView names an archive checkpoint explicitly. It never moves
// live monotonic fences backwards and never infers admission time from a clock.
func (s *ServiceActorSession) TokenHistoricalView(ctx context.Context, seqno uint64) (*ServiceActorSession, error) {
	if s == nil || s.reader == nil || seqno == 0 || seqno > s.seqno {
		return nil, errors.New("historical token checkpoint is not finalized by this session")
	}
	type observation struct {
		Root, File string
		Time       int64
	}
	value, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (observation, error) {
		var header tokenBlockHeader
		if err := node.client.Call(ctx, "getBlockHeader", struct {
			Workchain int32  `json:"workchain"`
			Shard     string `json:"shard"`
			Seqno     uint64 `json:"seqno"`
		}{-1, masterchainShard, seqno}, &header); err != nil {
			return observation{}, err
		}
		if header.Type != "blocks.header" || header.ID.Type != "tos.blockIdExt" || header.ID.Workchain != -1 || header.ID.Seqno != seqno || header.GenTime <= 0 || uint64(header.GenTime) > uint64(^uint32(0)) || (!s.chainTime.IsZero() && header.GenTime > s.chainTime.Unix()) {
			return observation{}, errors.New("historical token block header is invalid")
		}
		root, file, err := blockHashes(header.ID)
		return observation{Root: root, File: file, Time: header.GenTime}, err
	})
	if err != nil {
		return nil, err
	}
	return &ServiceActorSession{reader: s.reader, seqno: seqno, nodes: append([]*rpcNode(nil), s.nodes...), chainTime: time.Unix(value.Time, 0).UTC(), root: value.Root, file: value.File}, nil
}

func tokenHistoryAddress(value *address.Address) (string, error) {
	b := cell.BeginCell()
	if err := b.StoreAddr(value); err != nil {
		return "", err
	}
	decoded, err := nativecore.DecodeMsgAddressCell(b.EndCell())
	if err != nil {
		return "", err
	}
	return decoded.Text(), nil
}

type tokenBlockHeader struct {
	Type                   string    `json:"@type"`
	ID                     blockID   `json:"id"`
	GenTime                int64     `json:"gen_utime"`
	GlobalID               int32     `json:"global_id"`
	Version                uint32    `json:"version"`
	AfterMerge             bool      `json:"after_merge"`
	BeforeSplit            bool      `json:"before_split"`
	AfterSplit             bool      `json:"after_split"`
	WantMerge              bool      `json:"want_merge"`
	WantSplit              bool      `json:"want_split"`
	ValidatorListHashShort uint32    `json:"validator_list_hash_short"`
	CatchainSeqno          uint32    `json:"catchain_seqno"`
	MinRefMCSeqno          uint32    `json:"min_ref_mc_seqno"`
	IsKeyBlock             bool      `json:"is_key_block"`
	PrevKeyBlockSeqno      uint32    `json:"prev_key_block_seqno"`
	StartLT                string    `json:"start_lt"`
	EndLT                  string    `json:"end_lt"`
	PrevBlocks             []blockID `json:"prev_blocks"`
	HeaderProof            string    `json:"header_proof"`
}

type tokenStoredMessage struct {
	message tlb.Message
	root    *cell.Cell
}

func tokenStoredOutMessages(root *cell.Cell, count uint16) ([]tokenStoredMessage, error) {
	ioCell, err := root.PeekRef(0)
	if err != nil {
		return nil, err
	}
	io, err := ioCell.BeginParse()
	if err != nil {
		return nil, err
	}
	hasIn, err := io.LoadBoolBit()
	if err != nil {
		return nil, err
	}
	if hasIn {
		if _, err = io.LoadRefCell(); err != nil {
			return nil, err
		}
	}
	dictionary, err := io.LoadDict(15)
	if err != nil {
		return nil, err
	}
	if err = tokenExhausted(io); err != nil {
		return nil, err
	}
	entries, err := tokenDictionaryEntries(dictionary, 15)
	if err != nil || len(entries) != int(count) {
		return nil, errors.New("out-message count differs")
	}
	result := make([]tokenStoredMessage, 0, len(entries))
	for index, entry := range entries {
		number, err := entry.Key.LoadUInt(15)
		if err != nil || number != uint64(index) {
			return nil, errors.New("non-contiguous out-message indexes")
		}
		message, err := entry.Value.LoadRefCell()
		if err != nil || tokenExhausted(entry.Value) != nil {
			return nil, errors.New("invalid stored out-message")
		}
		data, err := message.BeginParse()
		if err != nil {
			return nil, err
		}
		var decoded tlb.Message
		if err = tlb.LoadFromCell(&decoded, data); err != nil {
			return nil, err
		}
		result = append(result, tokenStoredMessage{message: decoded, root: message})
	}
	return result, nil
}

// TokenWalletHistory is a bounded, hash-linked wallet history from this same
// finalized checkpoint. Wallet-specific external logs do not become actor logs.
type TokenWalletHistory struct {
	Result       HistoryResult           `json:"result"`
	Head         ActorTxID               `json:"head"`
	Transactions []TokenActorTransaction `json:"transactions"`
	BlockRoot    string                  `json:"block_root"`
	BlockFile    string                  `json:"block_file"`
}

func (s *ServiceActorSession) TokenWalletHistory(ctx context.Context, wallet string, anchor *ActorTxID) (*TokenWalletHistory, error) {
	if s == nil || s.reader == nil {
		return nil, errors.New("token session is required")
	}
	canonical, err := CanonicalAddress(wallet)
	if err != nil || canonical != wallet || !strings.HasPrefix(wallet, "0:") {
		return nil, errors.New("invalid token wallet address")
	}
	history, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (TokenWalletHistory, error) {
		if err := s.tokenVerifyEndpointNetwork(ctx, node); err != nil {
			return TokenWalletHistory{}, err
		}
		last, root, file, err := finalizedActorLastTransaction(ctx, node, wallet, s.seqno)
		if err != nil {
			return TokenWalletHistory{}, err
		}
		raw, result, err := walkHistoryEntries(ctx, node, wallet, last, anchor, s.reader.maxHistory)
		switch {
		case errors.Is(err, ErrHistoryAnchorMissing):
			return TokenWalletHistory{Result: historyAnchorMissing, BlockRoot: root, BlockFile: file}, nil
		case errors.Is(err, ErrHistoryBoundExceeded):
			return TokenWalletHistory{Result: historyBoundExceeded, BlockRoot: root, BlockFile: file}, nil
		case err != nil:
			return TokenWalletHistory{}, err
		}
		transactions := make([]TokenActorTransaction, 0, len(raw))
		for _, entry := range raw {
			account, err := hex.DecodeString(strings.TrimPrefix(wallet, "0:"))
			if err != nil || !bytes.Equal(entry.transaction.AccountAddr, account) {
				return TokenWalletHistory{}, errors.New("wallet history contains another account's transaction")
			}
			if !s.chainTime.IsZero() && int64(entry.transaction.Now) > s.chainTime.Unix() {
				return TokenWalletHistory{}, errors.New("wallet transaction is newer than its checkpoint")
			}
			tx, err := reduceTokenWalletTransaction(entry.transaction, entry.root)
			if err != nil {
				return TokenWalletHistory{}, err
			}
			transactions = append(transactions, tx)
		}
		head := ActorTxID{}
		if len(transactions) > 0 {
			head = ActorTxID{LT: transactions[0].LT, Hash: transactions[0].Hash}
		} else if anchor != nil {
			head = *anchor
		}
		return TokenWalletHistory{Result: result, Head: head, Transactions: transactions, BlockRoot: root, BlockFile: file}, nil
	})
	if err != nil {
		return nil, err
	}
	if err = s.pinHashes(history.BlockRoot, history.BlockFile); err != nil {
		return nil, err
	}
	if history.Result == historyAnchorMissing {
		return nil, ErrHistoryAnchorMissing
	}
	if history.Result == historyBoundExceeded {
		return nil, ErrHistoryBoundExceeded
	}
	return &history, nil
}

// tokenWalletAnchoredRead is one node's answer for a named wallet transaction.
type tokenWalletAnchoredRead struct {
	Result      HistoryResult         `json:"result"`
	Transaction TokenActorTransaction `json:"transaction"`
	BlockRoot   string                `json:"block_root"`
	BlockFile   string                `json:"block_file"`
}

// TokenWalletTransaction reads one named wallet transaction at this session's
// finalized checkpoint. It walks the hash- and logical-time-linked chain from
// the wallet's finalized last transaction down to the named one, so only the
// transactions after it count toward the history bound; the wallet's earlier
// history is never read. A named transaction that is not on that chain, or
// one further back than the bound, is an error.
func (s *ServiceActorSession) TokenWalletTransaction(ctx context.Context, wallet string, id ActorTxID) (*TokenActorTransaction, error) {
	if s == nil || s.reader == nil {
		return nil, errors.New("token session is required")
	}
	canonical, err := CanonicalAddress(wallet)
	if err != nil || canonical != wallet || !strings.HasPrefix(wallet, "0:") {
		return nil, errors.New("invalid token wallet address")
	}
	if id.LT == 0 {
		return nil, errors.New("named wallet transaction needs a logical time")
	}
	if raw, err := hex.DecodeString(id.Hash); err != nil || len(raw) != 32 || hex.EncodeToString(raw) != id.Hash {
		return nil, errors.New("named wallet transaction needs a lowercase 32-byte hash")
	}
	account, err := hex.DecodeString(strings.TrimPrefix(wallet, "0:"))
	if err != nil {
		return nil, err
	}
	read, _, err := quorumRead(ctx, s.nodes, s.reader.chain.quorum, func(ctx context.Context, node *rpcNode) (tokenWalletAnchoredRead, error) {
		if err := s.tokenVerifyEndpointNetwork(ctx, node); err != nil {
			return tokenWalletAnchoredRead{}, err
		}
		last, root, file, err := finalizedActorLastTransaction(ctx, node, wallet, s.seqno)
		if err != nil {
			return tokenWalletAnchoredRead{}, err
		}
		entry, err := walkToHistoryEntry(ctx, node, wallet, last, id, s.reader.maxHistory)
		switch {
		case errors.Is(err, ErrHistoryAnchorMissing):
			return tokenWalletAnchoredRead{Result: historyAnchorMissing, BlockRoot: root, BlockFile: file}, nil
		case errors.Is(err, ErrHistoryBoundExceeded):
			return tokenWalletAnchoredRead{Result: historyBoundExceeded, BlockRoot: root, BlockFile: file}, nil
		case err != nil:
			return tokenWalletAnchoredRead{}, err
		}
		if !bytes.Equal(entry.transaction.AccountAddr, account) {
			return tokenWalletAnchoredRead{}, errors.New("wallet history contains another account's transaction")
		}
		if !s.chainTime.IsZero() && int64(entry.transaction.Now) > s.chainTime.Unix() {
			return tokenWalletAnchoredRead{}, errors.New("wallet transaction is newer than its checkpoint")
		}
		tx, err := reduceTokenWalletTransaction(entry.transaction, entry.root)
		if err != nil {
			return tokenWalletAnchoredRead{}, err
		}
		return tokenWalletAnchoredRead{Result: HistoryAnchorReached, Transaction: tx, BlockRoot: root, BlockFile: file}, nil
	})
	if err != nil {
		return nil, err
	}
	if err = s.pinHashes(read.BlockRoot, read.BlockFile); err != nil {
		return nil, err
	}
	switch read.Result {
	case historyAnchorMissing:
		return nil, ErrHistoryAnchorMissing
	case historyBoundExceeded:
		return nil, ErrHistoryBoundExceeded
	case HistoryAnchorReached:
	default:
		return nil, errors.New("invalid anchored wallet read")
	}
	if read.Transaction.LT != id.LT || read.Transaction.Hash != id.Hash {
		return nil, errors.New("anchored wallet read returned another transaction")
	}
	return &read.Transaction, nil
}

// walkToHistoryEntry pages backwards from last with the same hash and
// logical-time continuity as walkHistoryEntries and returns the named entry
// itself. At most bound newer transactions are passed on the way.
func walkToHistoryEntry(ctx context.Context, node *rpcNode, address string, last transactionID, target ActorTxID, bound int) (historyEntry, error) {
	next := last
	passed := 0
	for {
		if next.LT == "0" || next.LT == "" {
			return historyEntry{}, ErrHistoryAnchorMissing
		}
		page, err := historyEntriesAt(ctx, node, address, next, actorHistoryPage)
		if err != nil {
			return historyEntry{}, err
		}
		for _, entry := range page {
			transaction := entry.transaction
			if transaction.LT == target.LT && hex.EncodeToString(transaction.Hash) == target.Hash {
				return entry, nil
			}
			if transaction.LT <= target.LT {
				return historyEntry{}, ErrHistoryAnchorMissing
			}
			if passed >= bound {
				return historyEntry{}, ErrHistoryBoundExceeded
			}
			passed++
		}
		oldest := page[len(page)-1].transaction
		if oldest.PrevTxLT == 0 {
			return historyEntry{}, ErrHistoryAnchorMissing
		}
		next = transactionID{Type: "internal.transactionId", LT: strconv.FormatUint(oldest.PrevTxLT, 10),
			Hash: base64.StdEncoding.EncodeToString(oldest.PrevTxHash)}
	}
}
func reduceTokenWalletTransaction(tx tlb.Transaction, root *cell.Cell) (TokenActorTransaction, error) {
	result := TokenActorTransaction{LT: tx.LT, Hash: hex.EncodeToString(tx.Hash), Now: tx.Now, Kind: "wallet_message"}
	if ordinary, ok := tx.Description.(tlb.TransactionDescriptionOrdinary); ok {
		if vm, ok := ordinary.ComputePhase.Phase.(tlb.ComputePhaseVM); ok {
			result.TookEffect = vm.Success && !ordinary.Aborted
			result.ExitCode = vm.Details.ExitCode
		}
	}
	if tx.IO.In != nil {
		message, err := storedInboundMessage(root)
		if err != nil {
			return result, err
		}
		result.InboundMessageHash = hex.EncodeToString(message.Hash())
		if tx.IO.In.MsgType == tlb.MsgTypeExternalIn {
			body := tx.IO.In.AsExternalIn().Body
			if body != nil {
				result.BodyBOC = bocText(body)
			}
		}
		if tx.IO.In.MsgType == tlb.MsgTypeInternal {
			in := tx.IO.In.AsInternal()
			result.Bounced = in.Bounced
			result.Sender, err = addressText(in.SrcAddr)
			if err != nil {
				return result, err
			}
			result.ValueNano = in.Amount.Nano().String()
			body := in.Body
			if body == nil {
				body = cell.BeginCell().EndCell()
			}
			result.BodyBOC = bocText(body)
		}
	}
	stored, err := tokenStoredOutMessages(root, tx.OutMsgCount)
	if err != nil {
		return result, err
	}
	for _, entry := range stored {
		if entry.message.MsgType != tlb.MsgTypeInternal {
			continue
		}
		out := entry.message.AsInternal()
		destination, err := addressText(out.DstAddr)
		if err != nil {
			return result, err
		}
		body := out.Body
		if body == nil {
			body = cell.BeginCell().EndCell()
		}
		result.Outputs = append(result.Outputs, TokenActorOutput{Hash: hex.EncodeToString(entry.root.Hash()), Destination: destination, ValueNano: out.Amount.Nano().String(), Bounce: out.Bounce, Bounced: out.Bounced, HasStateInit: out.StateInit != nil, BodyBOC: bocText(body)})
	}
	return result, nil
}

func (s *ServiceActorSession) tokenVerifyEndpointNetwork(ctx context.Context, node *rpcNode) error {
	if s.reader.network == nil {
		return errors.New("token history has no pinned network")
	}
	var result struct {
		Type          string  `json:"@type"`
		Last          blockID `json:"last"`
		StateRootHash string  `json:"state_root_hash"`
		Init          blockID `json:"init"`
	}
	if err := node.client.Call(ctx, "getMasterchainInfo", struct{}{}, &result); err != nil {
		return err
	}
	if result.Type != "blocks.masterchainInfo" || result.Last.Seqno < s.seqno {
		return errors.New("token history endpoint is stale or malformed")
	}
	root, err := base64.StdEncoding.DecodeString(result.Init.RootHash)
	if err != nil || len(root) != 32 || "sha256:"+hex.EncodeToString(root) != s.reader.network.GenesisRootHash {
		return errors.New("token history genesis root mismatch")
	}
	file, err := base64.StdEncoding.DecodeString(result.Init.FileHash)
	if err != nil || len(file) != 32 || "sha256:"+hex.EncodeToString(file) != s.reader.network.GenesisFileHash {
		return errors.New("token history genesis file mismatch")
	}
	return nil
}
