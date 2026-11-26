package buyersdk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func tokenSenderBody(p *TokenPreparedMessage) (*cell.Cell, uint64, error) {
	if p == nil || p.Version != TokenPreparedMessageVersion || !p.Bounce || !isRawAddress(p.Sender) || !isRawAddress(p.Destination) {
		return nil, 0, errors.New("invalid exact token message")
	}
	value, ok := new(big.Int).SetString(p.ValueNanotos, 10)
	if !ok || value.Sign() <= 0 {
		return nil, 0, ErrUnsupportedAmount
	}
	amount, err := u64Amount(value)
	if err != nil {
		return nil, 0, err
	}
	raw, err := base64.StdEncoding.DecodeString(p.BodyBOC)
	if err != nil {
		return nil, 0, err
	}
	body, err := cell.FromBOC(raw)
	if err != nil || hex.EncodeToString(body.Hash()) != p.BodyHash {
		return nil, 0, errors.New("token body hash differs")
	}
	return body, amount, nil
}

// PreflightToken verifies the exact wallet transfer without broadcasting it.
func (s *TOSCTLServiceActorSender) PreflightToken(ctx context.Context, p *TokenPreparedMessage, validUntil uint32) error {
	if s == nil || ctx == nil || validUntil == 0 {
		return errors.New("missing token custody")
	}
	body, amount, err := tokenSenderBody(p)
	if err != nil {
		return err
	}
	if err = s.checkSubmissionEndpoints(ctx); err != nil {
		return err
	}
	raw, err := s.run(ctx, "wallet", "send", "--from", s.wallet, "--to", p.Destination, "--amount-nanotos", fmt.Sprint(amount), "--body-boc", p.BodyBOC, "--bounce", "--valid-until", fmt.Sprint(validUntil), "--build-only")
	if err != nil {
		return errors.New("tosctl could not prepare the token wallet binding check")
	}
	var result struct {
		Version     string `json:"version"`
		ValidUntil  uint32 `json:"valid_until"`
		Wallet      string `json:"wallet"`
		Payer       string `json:"payer"`
		Destination string `json:"destination"`
		Amount      uint64 `json:"amount_nanotos"`
		BodyHash    string `json:"body_hash"`
		StateInit   string `json:"state_init_hash"`
		Message     string `json:"message_boc_base64"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&result) != nil || result.Version != "tosctl.wallet-prepared-send.v2" || result.ValidUntil != validUntil || result.Wallet != s.wallet || !sameAddress(result.Payer, p.Sender) || !sameAddress(result.Destination, p.Destination) || result.Amount != amount || result.BodyHash != cellHash(body) || result.StateInit != "" || result.Message == "" {
		return errors.New("tosctl prepared a message other than the confirmed token transfer")
	}
	var extra any
	if err = d.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("token wallet preflight has trailing data")
	}
	return nil
}

// SendToken carries the persisted body and amount unchanged. Any uncertain
// subprocess result remains ambiguous and must be resolved from finalized state.
func (s *TOSCTLServiceActorSender) SendToken(ctx context.Context, p *TokenPreparedMessage, validUntil uint32) error {
	if s == nil || ctx == nil || validUntil == 0 {
		return ErrCallNotStarted
	}
	_, amount, err := tokenSenderBody(p)
	if err != nil {
		return fmt.Errorf("%w: invalid token message", ErrCallNotStarted)
	}
	out, err := s.runWithPath(ctx, "wallet", "send", "--from", s.wallet, "--to", p.Destination, "--amount-nanotos", fmt.Sprint(amount), "--body-boc", p.BodyBOC, "--bounce", "--valid-until", fmt.Sprint(validUntil), "--yes")
	if errors.Is(err, ErrCallNotStarted) {
		return err
	}
	if err != nil {
		return errors.New("token wallet submission outcome is ambiguous")
	}
	if !bytes.Contains(out, []byte("Transfer sent")) {
		return errors.New("token wallet submission outcome is ambiguous: no submission report")
	}
	return nil
}
