// token-issuer-fixture drives the production read path for isolated acceptance
// tests. It is not a signing tool and holds no custody or source transaction key.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/pkg/tokenissuer"
)

func run() error {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
	if err != nil {
		return err
	}
	if len(raw) > 65536 {
		return errors.New("fixture input limit")
	}
	var request struct {
		Policy   tokenissuer.Policy `json:"policy"`
		Receiver string             `json:"receiver"`
		Amount   string             `json:"amount"`
		Now      *int64             `json:"now_unix,omitempty"`
	}
	if err = jsonstrict.Decode(raw, &request); err != nil {
		return err
	}
	if len(request.Amount) > 37 {
		return errors.New("amount limit")
	}
	amount, ok := new(big.Int).SetString(request.Amount, 10)
	if !ok || amount.String() != request.Amount {
		return errors.New("invalid amount")
	}
	clock := time.Now
	if request.Now != nil {
		clock = func() time.Time { return time.Unix(*request.Now, 0) }
	}
	reader, err := tokenissuer.NewReader(request.Policy, clock)
	if err != nil {
		return err
	}
	snapshot, err := reader.Read(context.Background(), request.Receiver)
	if err != nil {
		return err
	}
	received, fee, err := snapshot.Received(amount)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Observation tokenissuer.Snapshot `json:"observation"`
		Received    string               `json:"received"`
		Fee         string               `json:"fee"`
	}{snapshot, received.String(), fee.String()})
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
