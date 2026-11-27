// Package tokenissuer reads issuer restrictions and fees at a finalized source
// block. It never signs or submits a transaction. Endpoint observations are not
// cross-domain proofs; the caller owns the chain, token and runtime-code pins.
package tokenissuer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
)

const (
	Standard         = "standard"
	Legacy           = "legacy_usdt"
	MaxAgeSeconds    = 1800
	MaxFutureSeconds = 30
	maxResponse      = 4 << 20
)

var addressPattern = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var quantityPattern = regexp.MustCompile(`^0x(?:0|[1-9a-fA-F][0-9a-fA-F]{0,63})$`)

// Policy is custody-owned configuration, never taken from a quote or gateway.
type Policy struct {
	RPCURL     string `json:"rpc_url"`
	ChainID    uint64 `json:"chain_id"`
	Token      string `json:"token"`
	Bridge     string `json:"bridge"`
	CodeSHA256 string `json:"code_sha256"`
	Profile    string `json:"profile"`
}

func validAddress(s string) bool {
	return addressPattern.MatchString(s) && s != "0x0000000000000000000000000000000000000000"
}
func (p Policy) Validate() error {
	u, err := url.Parse(p.RPCURL)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid issuer endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return errors.New("issuer endpoint requires TLS or numeric loopback")
	}
	if p.ChainID == 0 || p.ChainID > 0xffffffff || !validAddress(p.Token) || !validAddress(p.Bridge) || !hashPattern.MatchString(p.CodeSHA256) || (p.Profile != Standard && p.Profile != Legacy) {
		return errors.New("invalid pinned issuer policy")
	}
	return nil
}

// Snapshot records one pinned observation; amounts are atomic integers.
type Snapshot struct {
	ChainID        uint64 `json:"chain_id"`
	Token          string `json:"token"`
	Receiver       string `json:"receiver"`
	BlockHash      string `json:"block_hash"`
	BlockNumber    string `json:"block_number"`
	BlockTime      uint64 `json:"block_time"`
	FeeBasisPoints uint64 `json:"fee_basis_points"`
	MaximumFee     string `json:"maximum_fee"`
}

type Reader struct {
	policy Policy
	now    func() time.Time
}

func NewReader(p Policy, now func() time.Time) (*Reader, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &Reader{policy: p, now: now}, nil
}

type rpc struct {
	client *http.Client
	url    string
	id     uint64
}

func (r *rpc) call(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	switch method {
	case "eth_chainId", "eth_getBlockByNumber", "eth_getCode", "eth_call":
	default:
		return nil, errors.New("unapproved issuer RPC method")
	}
	// One observation makes fewer than sixteen calls; the id cannot overflow.
	if r.id >= 16 {
		return nil, errors.New("issuer RPC call budget exceeded")
	}
	r.id++
	if params == nil {
		params = []any{}
	}
	request, err := json.Marshal(struct {
		JSONRPC string `json:"jsonrpc"`
		ID      uint64 `json:"id"`
		Method  string `json:"method"`
		Params  []any  `json:"params"`
	}{"2.0", r.id, method, params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(request))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := r.client.Do(req)
	if err != nil {
		return nil, errors.New("issuer RPC unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("issuer RPC refused")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponse+1))
	if err != nil || len(body) > maxResponse {
		return nil, errors.New("issuer RPC response limit or read failure")
	}
	var answer struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      uint64          `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err = jsonstrict.Decode(body, &answer); err != nil || answer.JSONRPC != "2.0" || answer.ID != r.id || len(answer.Error) != 0 || len(answer.Result) == 0 || bytes.Equal(answer.Result, []byte("null")) {
		return nil, errors.New("malformed or failed issuer RPC response")
	}
	return answer.Result, nil
}
func text(raw json.RawMessage) (string, error) {
	var s string
	err := jsonstrict.Decode(raw, &s)
	return s, err
}
func quantity(s string) (*big.Int, error) {
	if !quantityPattern.MatchString(s) {
		return nil, errors.New("invalid issuer quantity")
	}
	n, ok := new(big.Int).SetString(s[2:], 16)
	if !ok {
		return nil, errors.New("invalid issuer quantity")
	}
	return n, nil
}
func word(raw json.RawMessage) (*big.Int, error) {
	s, err := text(raw)
	if err != nil || len(s) != 66 || s[:2] != "0x" {
		return nil, errors.New("invalid issuer ABI word")
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
func header(raw json.RawMessage) (map[string]json.RawMessage, string, uint64, error) {
	var fields map[string]json.RawMessage
	if err := jsonstrict.Decode(raw, &fields); err != nil {
		return nil, "", 0, err
	}
	h, err := text(fields["hash"])
	if err != nil || len(h) != 66 || h[:2] != "0x" || !hashPattern.MatchString(h[2:]) {
		return nil, "", 0, errors.New("invalid finalized issuer block hash")
	}
	stamp, err := text(fields["timestamp"])
	if err != nil {
		return nil, "", 0, err
	}
	n, err := quantity(stamp)
	if err != nil || !n.IsUint64() {
		return nil, "", 0, errors.New("invalid issuer block time")
	}
	number, err := text(fields["number"])
	if err != nil {
		return nil, "", 0, err
	}
	if _, err = quantity(number); err != nil {
		return nil, "", 0, err
	}
	return fields, h, n.Uint64(), nil
}
func (r *Reader) fresh(stamp uint64) error {
	now := r.now().Unix()
	if now < 0 {
		return errors.New("invalid issuer clock")
	}
	seconds := uint64(now)
	if (stamp > seconds && stamp-seconds > MaxFutureSeconds) || (seconds > stamp && seconds-stamp > MaxAgeSeconds) {
		return errors.New("issuer finalized read is stale or future-dated")
	}
	return nil
}

func (r *Reader) Read(ctx context.Context, receiver string) (Snapshot, error) {
	var result Snapshot
	if !validAddress(receiver) {
		return result, errors.New("invalid issuer receiver")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("issuer redirect refused") }}
	rpc := rpc{client: client, url: r.policy.RPCURL}
	raw, err := rpc.call(ctx, "eth_chainId")
	if err != nil {
		return result, err
	}
	s, err := text(raw)
	if err != nil {
		return result, err
	}
	id, err := quantity(s)
	if err != nil || !id.IsUint64() || id.Uint64() != r.policy.ChainID {
		return result, errors.New("issuer chain differs")
	}
	raw, err = rpc.call(ctx, "eth_getBlockByNumber", "finalized", false)
	if err != nil {
		return result, err
	}
	fields, hash, stamp, err := header(raw)
	if err != nil {
		return result, err
	}
	if err = r.fresh(stamp); err != nil {
		return result, err
	}
	point := map[string]any{"blockHash": hash, "requireCanonical": true}
	raw, err = rpc.call(ctx, "eth_getCode", r.policy.Token, point)
	if err != nil {
		return result, err
	}
	code, err := text(raw)
	if err != nil || len(code) < 4 || len(code)%2 != 0 || code[:2] != "0x" {
		return result, errors.New("invalid issuer runtime code")
	}
	decoded, err := hex.DecodeString(code[2:])
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(decoded)
	if hex.EncodeToString(digest[:]) != r.policy.CodeSHA256 {
		return result, errors.New("issuer code differs")
	}
	read := func(selector, arg string) (*big.Int, error) {
		raw, err := rpc.call(ctx, "eth_call", map[string]string{"to": r.policy.Token, "data": "0x" + selector + arg}, point)
		if err != nil {
			return nil, err
		}
		return word(raw)
	}
	boolean := func(selector, arg string) (bool, error) {
		n, err := read(selector, arg)
		if err != nil {
			return false, err
		}
		if !n.IsUint64() || n.Uint64() > 1 {
			return false, errors.New("noncanonical issuer boolean")
		}
		return n.Uint64() == 1, nil
	}
	selector := "fe575a87"
	if r.policy.Profile == Legacy {
		selector = "e47d6060"
	}
	blocked, err := boolean(selector, "000000000000000000000000"+receiver[2:])
	if err != nil {
		return result, err
	}
	if blocked {
		return result, errors.New("issuer receiver is blacklisted")
	}
	paused, err := boolean("5c975abb", "")
	if err != nil {
		return result, err
	}
	if paused {
		return result, errors.New("issuer token is paused")
	}
	rate := new(big.Int)
	maximum := new(big.Int)
	if r.policy.Profile == Legacy {
		deprecated, err := boolean("0e136b19", "")
		if err != nil {
			return result, err
		}
		if deprecated {
			return result, errors.New("issuer token is deprecated")
		}
		rate, err = read("dd644f72", "")
		if err != nil {
			return result, err
		}
		maximum, err = read("35390714", "")
		if err != nil {
			return result, err
		}
	}
	if !rate.IsUint64() || rate.Uint64() >= 10000 {
		return result, errors.New("issuer fee rate is outside bounds")
	}
	number, err := text(fields["number"])
	if err != nil {
		return result, err
	}
	raw, err = rpc.call(ctx, "eth_getBlockByNumber", number, false)
	if err != nil {
		return result, err
	}
	_, sameHash, _, err := header(raw)
	if err != nil {
		return result, err
	}
	if sameHash != hash {
		return result, errors.New("issuer checkpoint changed")
	}
	if err = r.fresh(stamp); err != nil {
		return result, err
	}
	return Snapshot{ChainID: r.policy.ChainID, Token: r.policy.Token, Receiver: receiver, BlockHash: hash, BlockNumber: number, BlockTime: stamp, FeeBasisPoints: rate.Uint64(), MaximumFee: maximum.String()}, nil
}

func (s Snapshot) Received(amount *big.Int) (*big.Int, *big.Int, error) {
	if amount == nil || amount.Sign() <= 0 || amount.BitLen() > 120 || s.FeeBasisPoints >= 10000 {
		return nil, nil, errors.New("invalid atomic amount or fee")
	}
	maximum, ok := new(big.Int).SetString(s.MaximumFee, 10)
	if !ok || maximum.Sign() < 0 || maximum.BitLen() > 256 || maximum.String() != s.MaximumFee {
		return nil, nil, errors.New("invalid issuer fee cap")
	}
	fee := new(big.Int).Mul(amount, new(big.Int).SetUint64(s.FeeBasisPoints))
	fee.Quo(fee, big.NewInt(10000))
	if fee.Cmp(maximum) > 0 {
		fee.Set(maximum)
	}
	received := new(big.Int).Sub(amount, fee)
	if received.Sign() <= 0 {
		return nil, nil, errors.New("issuer fee consumes full amount")
	}
	return received, fee, nil
}
