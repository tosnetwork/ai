package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/jsonstrict"
	"github.com/tosnetwork/ai/protocol/pkg/purchaseevidence"
	"github.com/tosnetwork/ai/protocol/pkg/toschain"
)

type openedToken struct {
	session   purchaseevidence.TokenSession
	endpoints []purchaseevidence.EndpointReport
	close     func()
}

var openTokenSession = func(ctx context.Context, config readConfig) (*openedToken, error) {
	opened, err := openChainSession(ctx, config)
	if err != nil {
		return nil, err
	}
	session, ok := opened.session.(purchaseevidence.TokenSession)
	if !ok {
		opened.close()
		return nil, errors.New("reader does not implement token sessions")
	}
	return &openedToken{session: session, endpoints: opened.endpoints, close: opened.close}, nil
}

func runTokenVerify(opts *options, network *nativev1.NetworkDomain, inputs []purchaseevidence.FileDigest, stdout, stderr io.Writer) int {
	raw, err := readFile(opts.assetPinsPath, maxNetworkFile, "asset-pins", &inputs)
	if err != nil {
		fmt.Fprintln(stderr, "tos-service-verify:", err)
		return exitUsage
	}
	var pins []toschain.TokenAssetPin
	if err = jsonstrict.Decode(raw, &pins); err != nil || len(pins) == 0 || len(pins) > toschain.MaxPinnedTokenAssets {
		fmt.Fprintln(stderr, "tos-service-verify: asset-pins must contain 1 or 2 supported releases")
		return exitUsage
	}
	var bundle *purchaseevidence.TokenBundle
	if opts.evidencePath != "" {
		raw, err = readFile(opts.evidencePath, purchaseevidence.MaxBundleBytes, "evidence", &inputs)
		if err == nil {
			bundle, err = purchaseevidence.DecodeTokenBundle(raw)
		}
		if err != nil {
			fmt.Fprintln(stderr, "tos-service-verify:", err)
			return exitUsage
		}
	}
	copyOpts := *opts
	copyOpts.evidencePath = ""
	if copyOpts.actor == "" && bundle != nil {
		copyOpts.actor = bundle.Actor
	}
	// Reuse bounded file and selector handling, without passing the token bundle
	// through the native bundle decoder.
	native, config, err := buildInput(&copyOpts, network, &inputs)
	if err != nil {
		fmt.Fprintln(stderr, "tos-service-verify:", err)
		return exitUsage
	}
	input := purchaseevidence.TokenInput{Network: network, Actor: native.Actor, ActorCodeHash: native.ActorCodeHash, Pins: pins, RequestIDs: native.RequestIDs, RequestHashes: native.RequestHashes, Bundle: bundle, Receipt: native.Receipt, Artifact: native.Artifact}
	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()
	opened, err := openTokenSession(ctx, config)
	var verdict *purchaseevidence.TokenVerdict
	if err != nil {
		verdict = &purchaseevidence.TokenVerdict{Schema: purchaseevidence.TokenVerdictSchema, Result: purchaseevidence.ResultFail, Network: purchaseevidence.NetworkTuple{NetworkID: network.NetworkId, GenesisRootHash: network.GenesisRootHash, GenesisFileHash: network.GenesisFileHash}, Checks: []purchaseevidence.Check{{ID: "finalized-read", Detail: err.Error()}}}
	} else {
		defer opened.close()
		verdict = purchaseevidence.VerifyToken(ctx, opened.session, input)
		verdict.Reads = &purchaseevidence.Reads{Endpoints: opened.endpoints, Quorum: config.quorum}
	}
	tool := buildTool("tos-service-verify")
	verdict.Tool = &tool
	verdict.Inputs = inputs
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err = enc.Encode(verdict); err != nil {
		fmt.Fprintln(stderr, "tos-service-verify:", err)
		return exitUsage
	}
	fmt.Fprintf(stderr, "token verdict: %s; checkpoint %d; %d requests\n", verdict.Result, verdict.Checkpoint.Seqno, len(verdict.Requests))
	for _, c := range verdict.Checks {
		if !c.OK {
			fmt.Fprintf(stderr, "FAILED %s: %s\n", c.ID, c.Detail)
		}
	}
	if verdict.Result != purchaseevidence.ResultPass {
		return exitFail
	}
	return exitPass
}
