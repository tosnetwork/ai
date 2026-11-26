package buyersdk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

// Lifecycle operations: the buyer's refund duties on a Service Actor
// request (SERVICE_ACTOR_TVM_V1 sections 7.3 to 7.5). Their names are the
// tosctl operation names.
const (
	LifecycleExpire      = "expire"
	LifecycleClaimRefund = "claim-refund"
	LifecycleSweep       = "sweep-expired-request"
)

func validLifecycle(operation string) bool {
	switch operation {
	case LifecycleExpire, LifecycleClaimRefund, LifecycleSweep:
		return true
	}
	return false
}

// LifecycleIntent is one lifecycle send. Destination is the claim_refund
// destination; the buyer always sets it to its own wallet.
type LifecycleIntent struct {
	Operation   string
	Actor       string
	RequestID   uint64
	QueryID     uint64
	Destination string
}

// LifecycleSubmission is what custody reported about the wallet message it
// signed for a lifecycle send: the seqno it consumes, the time after which
// the wallet refuses it, and its exact hash. Announced is false when custody
// reported none of it.
type LifecycleSubmission struct {
	Announced      bool
	Seqno          uint32
	ValidUntilUnix int64
	// MessageHash is the external message's lowercase hex hash.
	MessageHash string
}

// ServiceActorLifecycleSender hands a lifecycle send to custody.
// ErrCallNotStarted means custody was never started; any other error
// leaves the outcome ambiguous. The submission is returned with either
// outcome, as far as custody reported it.
type ServiceActorLifecycleSender interface {
	SendLifecycle(ctx context.Context, intent LifecycleIntent) (LifecycleSubmission, error)
}

// walletMessageLine is the line tosctl prints once it has signed a wallet
// message and before it broadcasts it.
var walletMessageLine = regexp.MustCompile(`(?m)^Wallet message seqno=([0-9]{1,10}) valid_until=([0-9]{1,10}|none) hash=sha256:([0-9a-f]{64})\r?$`)

// parseWalletMessage reads tosctl's wallet message line. Exactly one line is
// trusted; none, or more than one, announces nothing. So does a message
// without an expiry (a V1R3 wallet): no rule could settle it by time.
func parseWalletMessage(output []byte) LifecycleSubmission {
	matches := walletMessageLine.FindAllSubmatch(output, -1)
	if len(matches) != 1 {
		return LifecycleSubmission{}
	}
	seqno, err := strconv.ParseUint(string(matches[0][1]), 10, 32)
	if err != nil {
		return LifecycleSubmission{}
	}
	validUntil, err := strconv.ParseUint(string(matches[0][2]), 10, 32)
	if err != nil || validUntil == 0 {
		return LifecycleSubmission{}
	}
	return LifecycleSubmission{Announced: true, Seqno: uint32(seqno), ValidUntilUnix: int64(validUntil),
		MessageHash: string(matches[0][3])}
}

// checkSubmissionEndpoints requires every endpoint tosctl would submit
// through to be a verified endpoint of the verified network.
func (s *TOSCTLServiceActorSender) checkSubmissionEndpoints(ctx context.Context) error {
	return checkTOSCTLEndpoints(ctx, s.runner.config, s.endpoints)
}

// checkTOSCTLEndpoints requires every endpoint a tosctl configuration
// submits through to be a verified endpoint of the verified network.
func checkTOSCTLEndpoints(ctx context.Context, config []byte, vetter EndpointVetter) error {
	endpoints, err := effectiveChainEndpoints(config)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	for _, endpoint := range vetter.Endpoints() {
		allowed[endpoint] = true
	}
	for _, endpoint := range endpoints {
		if !allowed[endpoint] {
			return fmt.Errorf("tosctl would submit through %s, which is not a verified endpoint", endpoint)
		}
		if err := vetter.CheckEndpointGenesis(ctx, endpoint); err != nil {
			return fmt.Errorf("tosctl endpoint %s is not on the verified network: %w", endpoint, err)
		}
	}
	return nil
}

// SendLifecycle runs `tosctl agent service send --operation <op>` for one
// request. claim-refund always names the buyer's destination. tosctl attaches
// the operation's allowance; its unused part returns.
func (s *TOSCTLServiceActorSender) SendLifecycle(ctx context.Context, intent LifecycleIntent) (LifecycleSubmission, error) {
	if s == nil || ctx == nil || !validLifecycle(intent.Operation) || !isRawAddress(intent.Actor) || intent.QueryID == 0 {
		return LifecycleSubmission{}, ErrCallNotStarted
	}
	if intent.Operation == LifecycleClaimRefund && !isRawAddress(intent.Destination) {
		return LifecycleSubmission{}, ErrCallNotStarted
	}
	if err := s.checkSubmissionEndpoints(ctx); err != nil {
		return LifecycleSubmission{}, errors.Join(ErrCallNotStarted, err)
	}
	args := []string{"agent", "service", "send", "--operation", intent.Operation, "--address", intent.Actor,
		"--from", s.wallet, "--query-id", strconv.FormatUint(intent.QueryID, 10),
		"--request-id", strconv.FormatUint(intent.RequestID, 10)}
	if intent.Operation == LifecycleClaimRefund {
		args = append(args, "--destination", intent.Destination)
	}
	output, err := s.runWithPath(ctx, append(args, "--yes")...)
	if errors.Is(err, ErrCallNotStarted) {
		return LifecycleSubmission{}, err
	}
	submission := parseWalletMessage(output)
	if err != nil {
		return submission, fmt.Errorf("tosctl %s outcome is ambiguous: %w", intent.Operation, err)
	}
	if !bytes.Contains(output, []byte("Service Actor "+intent.Operation+" message submitted to")) {
		return submission, fmt.Errorf("tosctl %s outcome is ambiguous: no submission report", intent.Operation)
	}
	return submission, nil
}

// LifecycleSend is one lifecycle send in a call's journal record. Its phase
// is sending, submitted or ambiguous, like a call's. Finalized history, not
// this entry, says whether the send took effect; the entry only bounds how
// often the buyer sends.
type LifecycleSend struct {
	PreparedTokenMessage *TokenPreparedMessage `json:"prepared_token_message,omitempty"`
	Operation            string                `json:"operation"`
	QueryID              uint64                `json:"query_id"`
	Phase                CallPhase             `json:"phase"`
	SentUnix             int64                 `json:"sent_unix"`
	// WalletSeqno is the buyer wallet's seqno at a finalized checkpoint read
	// before the send.
	WalletSeqno uint32 `json:"wallet_seqno"`
	// ValidUntilBoundUnix bounds the valid_until of the wallet message the
	// send signs, from the send's start; it is used only when custody's
	// report of the message is missing.
	ValidUntilBoundUnix int64 `json:"valid_until_bound_unix"`
	// WalletAnchor is the buyer wallet's last finalized transaction before
	// the send; the wallet history read later starts after it.
	WalletAnchorLT   uint64 `json:"wallet_anchor_lt"`
	WalletAnchorHash string `json:"wallet_anchor_hash"`
	// Announced, SignedSeqno, ValidUntilUnix and MessageHash are custody's
	// report of the wallet message it signed (LifecycleSubmission). Token sends
	// also store their explicit command-line expiry in ValidUntilUnix, without
	// claiming a signed seqno or message hash that custody did not report.
	Announced      bool   `json:"announced,omitempty"`
	SignedSeqno    uint32 `json:"signed_seqno,omitempty"`
	ValidUntilUnix int64  `json:"valid_until_unix,omitempty"`
	MessageHash    string `json:"message_hash,omitempty"`
}

// Lifecycle send timing. Custody is given LifecycleSendTimeout to sign and
// broadcast. A send whose report custody gave carries the message's exact
// valid_until. Only for a send whose report was lost (the agent stopped
// during the send) is valid_until bounded instead: the send's start, plus
// LifecycleSendTimeout, plus the pinned tosctl's wallet message lifetime
// (FallbackWalletMessageLifetime), plus LifecycleClockSkew between the
// local clock and chain time.
const (
	LifecycleSendTimeout          = 3 * time.Minute
	FallbackWalletMessageLifetime = 2 * time.Minute
	LifecycleClockSkew            = 5 * time.Minute
)

// LifecycleValidUntilBound is the fallback valid_until bound of a send
// started at sent.
func LifecycleValidUntilBound(sent time.Time) int64 {
	return sent.Add(LifecycleSendTimeout + FallbackWalletMessageLifetime + LifecycleClockSkew).Unix()
}

var (
	// ErrNoLifecycleSender reports a buyer configured without one.
	ErrNoLifecycleSender = errors.New("the buyer has no lifecycle sender")
	// ErrLifecycleUnsettled reports an earlier send of the same operation
	// whose message may still execute: it is not sent again until finalized
	// state proves that the earlier message executed or can never execute.
	ErrLifecycleUnsettled = errors.New("an earlier send of this operation may still execute")
)

// SendLifecycle sends one lifecycle operation for an admitted call. The
// send is journaled before custody starts. A crash or a panic during it
// leaves the entry ambiguous. The destination of a claim_refund is always
// the buyer wallet, which made the call.
//
// An operation already handed to custody is sent again only when every
// earlier send of it is settled at a fresh finalized checkpoint (see
// lifecycleSettled); otherwise SendLifecycle returns ErrLifecycleUnsettled
// and sends nothing.
func (b *ServiceActorBuyer) SendLifecycle(ctx context.Context, requestHash, operation string) (CallRecord, error) {
	if record, err := b.config.Journal.Read(requestHash); err != nil {
		return CallRecord{}, err
	} else if isTokenCallRecord(record) {
		return b.sendTokenLifecycle(ctx, record, operation)
	}
	if b.config.Lifecycle == nil {
		return CallRecord{}, ErrNoLifecycleSender
	}
	if !validLifecycle(operation) {
		return CallRecord{}, fmt.Errorf("unknown lifecycle operation %q", operation)
	}
	before, err := b.config.Journal.Read(requestHash)
	if err != nil {
		return CallRecord{}, err
	}
	session, err := b.config.Reader.BeginBuyerSession(ctx)
	if err != nil {
		return before, errors.Join(ErrCallNotStarted, err)
	}
	seqno, err := session.WalletSeqno(ctx, b.config.BuyerWallet)
	if err != nil {
		return before, errors.Join(ErrCallNotStarted, fmt.Errorf("read the buyer wallet seqno: %w", err))
	}
	anchor, err := session.WalletLastTransaction(ctx, b.config.BuyerWallet)
	if err != nil {
		return before, errors.Join(ErrCallNotStarted, fmt.Errorf("read the buyer wallet's last transaction: %w", err))
	}
	if err := b.lifecycleSettled(ctx, session, before, operation, seqno); err != nil {
		return before, err
	}
	queryID, err := b.queryID()
	if err != nil {
		return CallRecord{}, err
	}
	now := b.config.Now()
	record, err := b.config.Journal.Transition(requestHash, []CallPhase{PhaseAdmitted}, func(r *CallRecord) error {
		if r.RequestID == nil {
			return errors.New("an admitted call without a request ID has no lifecycle duties")
		}
		if len(r.Lifecycle) != len(before.Lifecycle) {
			return ErrLifecycleUnsettled
		}
		r.Lifecycle = append(r.Lifecycle, LifecycleSend{Operation: operation, QueryID: queryID, Phase: PhaseSending,
			SentUnix: now.Unix(), WalletSeqno: seqno, ValidUntilBoundUnix: LifecycleValidUntilBound(now),
			WalletAnchorLT: anchor.LT, WalletAnchorHash: anchor.Hash})
		r.UpdatedUnix = now.Unix()
		return nil
	})
	if err != nil {
		return record, err
	}
	finish := func(phase CallPhase, submission LifecycleSubmission) (CallRecord, error) {
		return b.config.Journal.Transition(requestHash, []CallPhase{PhaseAdmitted}, func(r *CallRecord) error {
			for index := range r.Lifecycle {
				if r.Lifecycle[index].QueryID == queryID && r.Lifecycle[index].Phase == PhaseSending {
					r.Lifecycle[index].Phase = phase
					if submission.Announced {
						entry := &r.Lifecycle[index]
						entry.Announced, entry.SignedSeqno = true, submission.Seqno
						entry.ValidUntilUnix, entry.MessageHash = submission.ValidUntilUnix, submission.MessageHash
					}
				}
			}
			r.UpdatedUnix = b.config.Now().Unix()
			return nil
		})
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			_, _ = finish(PhaseAmbiguous, LifecycleSubmission{})
			panic(recovered)
		}
	}()
	// The deadline bounds when custody can sign, and so the message's
	// valid_until that the journal entry records.
	sendContext, cancel := context.WithDeadline(ctx, now.Add(LifecycleSendTimeout))
	defer cancel()
	submission, sendErr := b.config.Lifecycle.SendLifecycle(sendContext, LifecycleIntent{Operation: operation, Actor: record.Actor,
		RequestID: *record.RequestID, QueryID: queryID, Destination: record.BuyerWallet})
	phase := PhaseSubmitted
	switch {
	case errors.Is(sendErr, ErrCallNotStarted):
		phase = PhasePrepared
	case sendErr != nil:
		phase = PhaseAmbiguous
	}
	updated, err := finish(phase, submission)
	if err != nil {
		return record, err
	}
	return updated, sendErr
}

// lifecycleSettled requires every earlier send of operation that was handed
// to custody to be settled at the session checkpoint, whose chain time is
// the clock. seqno is the buyer wallet's seqno at that checkpoint. An
// earlier send is settled when one of these holds:
//
//  1. the actor's finalized history since the call holds a transaction from
//     the buyer wallet carrying the send's query_id: the message executed,
//     whatever its outcome, and cannot execute twice;
//  2. the checkpoint is past the message's valid_until and the wallet has
//     not consumed its seqno: it has expired before it could execute. For a
//     send custody reported, valid_until and the seqno are the signed ones.
//     For a send whose report was lost, they are the fallback bound and the
//     seqno read before the send;
//  3. for a send custody reported, the wallet's finalized history since the
//     send's anchor is read. It may hold the transaction of the send's exact
//     message: if that transaction sent nothing to the actor with the send's
//     query_id, the send reached no actor and is settled; otherwise rule 1
//     settles it once the actor's transaction is finalized. If the history
//     does not hold it, but the wallet's seqno has moved past the signed one,
//     a different message consumed that seqno and the send can never execute.
//
// Anything else leaves the earlier message possibly in flight, and the
// operation is not sent again.
func (b *ServiceActorBuyer) lifecycleSettled(ctx context.Context, session ServiceActorSession, record CallRecord,
	operation string, seqno uint32) error {
	chainTime := session.ChainTime().Unix()
	var history *toschain.ActorHistory
	wallets := map[toschain.ActorTxID]*toschain.WalletHistory{}
	for _, sent := range record.Lifecycle {
		if sent.Operation != operation || sent.Phase == PhasePrepared {
			continue
		}
		if sent.Announced {
			if sent.ValidUntilUnix > 0 && chainTime > sent.ValidUntilUnix && seqno <= sent.SignedSeqno {
				continue
			}
		} else if sent.ValidUntilBoundUnix > 0 && chainTime > sent.ValidUntilBoundUnix && seqno == sent.WalletSeqno {
			continue
		}
		if history == nil {
			anchor := &toschain.ActorTxID{LT: record.CallTransactionLT, Hash: record.CallTransactionHex}
			if anchor.LT == 0 || anchor.Hash == "" {
				return ErrLifecycleUnsettled
			}
			read, err := session.History(ctx, record.Actor, anchor)
			if err != nil {
				return errors.Join(ErrCallNotStarted, fmt.Errorf("read the actor history since the call: %w", err))
			}
			if read.Result != toschain.HistoryAnchorReached {
				return ErrLifecycleUnsettled
			}
			history = read
		}
		executed := false
		for _, transaction := range history.Transactions {
			if transaction.Sender != record.BuyerWallet {
				continue
			}
			if query, known := transaction.InboundQueryID(); known && query == sent.QueryID {
				executed = true
			}
		}
		if executed {
			continue
		}
		if !sent.Announced || sent.MessageHash == "" || sent.WalletAnchorLT == 0 || sent.WalletAnchorHash == "" {
			return ErrLifecycleUnsettled
		}
		anchor := toschain.ActorTxID{LT: sent.WalletAnchorLT, Hash: sent.WalletAnchorHash}
		wallet, read := wallets[anchor]
		if !read {
			var err error
			wallet, err = session.WalletHistory(ctx, record.BuyerWallet, anchor)
			if err != nil {
				return errors.Join(ErrCallNotStarted, fmt.Errorf("read the buyer wallet history since the send: %w", err))
			}
			wallets[anchor] = wallet
		}
		found, toActor := false, false
		for _, transaction := range wallet.Transactions {
			if transaction.ExternalMessageHash != sent.MessageHash {
				continue
			}
			found = true
			for _, out := range transaction.Out {
				if out.Destination == record.Actor && out.Known && out.QueryID == sent.QueryID {
					toActor = true
				}
			}
		}
		switch {
		case found && !toActor:
			// The exact message executed in the wallet and sent the actor
			// nothing for this send.
			continue
		case !found && seqno > sent.SignedSeqno:
			// Another message consumed the signed seqno.
			continue
		}
		return ErrLifecycleUnsettled
	}
	return nil
}

// CheckSubmissionEndpoints checks a pinned custody configuration against the
// finalized reader before an application broadcasts its journaled exact BOC.
func CheckSubmissionEndpoints(ctx context.Context, config []byte, vetter EndpointVetter) error {
	if ctx == nil || vetter == nil {
		return errors.New("missing custody endpoint verifier")
	}
	return checkTOSCTLEndpoints(ctx, config, vetter)
}
