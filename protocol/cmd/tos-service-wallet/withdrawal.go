package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
)

func confirmWithdrawalCommand(ctx context.Context, args []string, output, diagnostics io.Writer) error {
	set := flag.NewFlagSet("confirm-withdrawal", flag.ContinueOnError)
	set.SetOutput(diagnostics)
	actionPath := set.String("action", "", "absolute path to the original withdrawal action JSON")
	configPath := set.String("registry-config", "", "owner-private finalized Registry read JSON")
	fence := set.String("registry-checkpoint", "", "absolute Registry checkpoint fence path")
	sequence := set.Uint64("prior-checkpoint", 0, "finalized masterchain checkpoint of the original predecessor")
	root := set.String("prior-root", "", "hex block root hash at the prior checkpoint")
	file := set.String("prior-file", "", "hex block file hash at the prior checkpoint")
	if err := set.Parse(args); err != nil {
		return err
	}
	priorRoot, rootErr := hex.DecodeString(*root)
	priorFile, fileErr := hex.DecodeString(*file)
	if set.NArg() != 0 || *sequence == 0 || rootErr != nil || fileErr != nil || len(priorRoot) != 32 || len(priorFile) != 32 {
		return errors.New("withdrawal confirmation requires the exact prior finalized checkpoint")
	}
	action, err := loadAction(*actionPath)
	if err != nil {
		return err
	}
	var config transportConfig
	if err := loadTransportConfig(*configPath, &config); err != nil {
		return err
	}
	resolver, _, err := openWalletRegistry(config, *fence)
	if err != nil {
		return err
	}
	checkpoint := &nativev1.DNSCheckpointV1{Workchain: -1, Sequence: *sequence, RootHash: priorRoot, FileHash: priorFile}
	proof, err := resolver.ConfirmDelegationWithdrawal(ctx, action, checkpoint)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(proof)
}
