package main

import (
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	nativev1 "github.com/tosnetwork/ai/protocol/gen/tos/service/v1"
	"github.com/tosnetwork/ai/protocol/internal/osguard"
	"github.com/tosnetwork/ai/protocol/pkg/agentcarrier"
	"github.com/tosnetwork/ai/protocol/pkg/agenttransport"
	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
	"github.com/tosnetwork/ai/protocol/pkg/nativecore"
)

type transportLocator struct{ *nativecore.Locator }

func (l transportLocator) Locate(hash, agent string) (string, error) {
	if hash != l.CodeHash {
		return "", errors.New("unexpected registry code hash")
	}
	identity, err := l.Locator.Locate(agent)
	return identity.Address, err
}

func buyerTransport(config agentConfig, network *nativev1.NetworkDomain, locator *nativecore.Locator,
	registry agenttransport.FinalizedStateReader, relays *relayClients) (buyeragent.TransportConfig, error) {
	transportNetwork := &nativev1.NetworkDomain{NetworkId: network.NetworkId,
		GenesisRootHash: strings.TrimPrefix(network.GenesisRootHash, "sha256:"),
		GenesisFileHash: strings.TrimPrefix(network.GenesisFileHash, "sha256:")}
	const profile = agenttransport.TestNetworkLegacyEpochZero
	resolver, err := agenttransport.NewLegacyTestNetworkResolver(profile, transportNetwork, registry)
	if err != nil {
		return buyeragent.TransportConfig{}, err
	}
	verifier, err := agenttransport.NewVerifier(agenttransport.Config{Mode: profile, Network: transportNetwork,
		ChainPolicy: agenttransport.ChainPolicy{RegistryCodeHashes: []string{locator.CodeHash}, Locator: transportLocator{locator}}}, resolver)
	if err != nil {
		return buyeragent.TransportConfig{}, err
	}
	delegation, err := readTransportFile(config.TransportDelegationFile, agenttransport.DelegationSize)
	if err != nil {
		return buyeragent.TransportConfig{}, err
	}
	seed, err := readTransportFile(config.TransportSeedFile, ed25519.SeedSize)
	if err != nil {
		return buyeragent.TransportConfig{}, err
	}
	defer clear(seed)
	return buyeragent.TransportConfig{Delegation: delegation, Key: ed25519.NewKeyFromSeed(seed), Verifier: verifier,
		Relay:       func(url string) (agentcarrier.Relay, error) { return relays.client(url) },
		Directories: config.RelayDirectories,
		Directory:   func(url string) (agentcarrier.Directory, error) { return relays.client(url) }}, nil
}

func readTransportFile(path string, size int) ([]byte, error) {
	const invalid = "transport material must be an owner-private regular file of the required size"
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New(invalid)
	}
	before, err := os.Lstat(path)
	if err != nil || !privateTransportFile(before, size) {
		return nil, errors.New(invalid)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New(invalid)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || !privateTransportFile(after, size) {
		return nil, errors.New(invalid)
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(size)+1))
	if err != nil || len(raw) != size {
		clear(raw)
		return nil, errors.New(invalid)
	}
	return raw, nil
}

func privateTransportFile(info os.FileInfo, size int) bool {
	return info.Mode().IsRegular() && info.Mode().Perm() == 0o600 && info.Size() == int64(size) && osguard.CurrentUserOwns(info)
}
