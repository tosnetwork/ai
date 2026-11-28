package toschain

import (
	"context"
	"encoding/hex"
	"errors"
)

// CheckNetworkGenesis obtains a strict-majority genesis identity before a
// finalized read. Registry data cannot itself establish its hosting chain.
func (a *Adapter) CheckNetworkGenesis(ctx context.Context, rootHash, fileHash string) error {
	if a == nil {
		return errors.New("network reader unavailable")
	}
	type identity struct{ Root, File string }
	got, _, err := quorumRead(ctx, a.nodes, a.quorum, func(ctx context.Context, node *rpcNode) (identity, error) {
		var answer struct {
			Type string  `json:"@type"`
			Init blockID `json:"init"`
		}
		if err := node.client.Call(ctx, "getMasterchainInfo", struct{}{}, &answer); err != nil {
			return identity{}, err
		}
		root, err := decodeBase64Hash(answer.Init.RootHash)
		if err != nil || answer.Type != "blocks.masterchainInfo" {
			return identity{}, errors.New("invalid genesis answer")
		}
		file, err := decodeBase64Hash(answer.Init.FileHash)
		if err != nil {
			return identity{}, errors.New("invalid genesis answer")
		}
		return identity{"sha256:" + hex.EncodeToString(root), "sha256:" + hex.EncodeToString(file)}, nil
	})
	if err != nil {
		return err
	}
	if got.Root != rootHash || got.File != fileHash {
		return errors.New("finalized endpoints name another genesis")
	}
	return nil
}
