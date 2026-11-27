#!/usr/bin/env python3
"""Remove one boundary check per overlay; require its named test to go red.

The checkout is never mutated. A build failure or an absent/duplicate anchor is
an error, not a killed mutant. Run under the same thermal guard as Go tests.
"""

import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "./protocol/pkg/agenttransport"
# name, source, unique old text, replacement, named test
MUTANTS = [
    (
        "verifier-network-allowlist",
        "verify.go",
        "if err := validateApprovedTestNetwork(c.Network); err != nil",
        "if err := validateApprovedTestNetwork(c.Network); false && err != nil",
        "TestVerifierRejectsUnapprovedNetworks",
    ),
    (
        "resolver-network-allowlist",
        "legacy.go",
        "if err := validateApprovedTestNetwork(network); err != nil",
        "if err := validateApprovedTestNetwork(network); false && err != nil",
        "TestLegacyResolverRejectsUnapprovedNetworks",
    ),
    (
        "local-global-id-pin",
        "networks.go",
        "network.NetworkId == localTestNetworkID",
        "true",
        "TestVerifierRejectsUnapprovedNetworks/production-identity",
    ),
    (
        "local-root-pin",
        "networks.go",
        "network.GenesisRootHash == localTestRoot",
        "true",
        "TestVerifierRejectsUnapprovedNetworks/local-root",
    ),
    (
        "local-file-pin",
        "networks.go",
        "network.GenesisFileHash == localTestFile",
        "true",
        "TestVerifierRejectsUnapprovedNetworks/local-file",
    ),
    (
        "public-global-id-pin",
        "networks.go",
        "network.NetworkId == publicTestNetworkID",
        "true",
        "TestVerifierRejectsUnapprovedNetworks/public-global-id",
    ),
    (
        "public-root-pin",
        "networks.go",
        "network.GenesisRootHash == publicTestRoot",
        "true",
        "TestVerifierRejectsUnapprovedNetworks/public-root",
    ),
    (
        "public-file-pin",
        "networks.go",
        "network.GenesisFileHash == publicTestFile",
        "true",
        "TestVerifierRejectsUnapprovedNetworks/public-file",
    ),
    (
        "source-network",
        "legacy.go",
        '(n.GenesisRootHash != r.network.GenesisRootHash && n.GenesisRootHash != "sha256:"+r.network.GenesisRootHash)',
        "false",
        "TestLegacyReaderUsesTheOriginalNetworkBeforeNormalization",
    ),
    (
        "legacy-epoch",
        "verify.go",
        "d.AuthorizationEpoch != 0 || s.CurrentEpoch != nil || s.AdmissionEpochs != nil || s.EpochCheckpoint != 0",
        "false",
        "TestProductionAndLegacyModes",
    ),
    (
        "legacy-adapter-gate",
        "legacy.go",
        "mode != TestNetworkLegacyEpochZero || source == nil",
        "source == nil",
        "TestLegacyAdapterIsExplicit",
    ),
    (
        "set-bound",
        "verify.go",
        "len(agent.DelegationDigests) > 128 || len(s.AdmissionEpochs) > 128",
        "false",
        "TestFinalizedSetBounds",
    ),
    (
        "cache-capacity",
        "verify.go",
        "len(v.passes) < v.config.CacheEntries",
        "true",
        "TestCacheCapacityAndClockRollback",
    ),
    (
        "time-after-read",
        "verify.go",
        "if err = checkUse(d, purpose, after); err != nil",
        "if err = checkUse(d, purpose, after); false && err != nil",
        "TestTimeAfterReadAtExpiration",
    ),
    (
        "size",
        "delegation.go",
        "len(b) != DelegationSize",
        "false",
        "TestFrozenVectors/trailing",
    ),
    (
        "production-gate",
        "verify.go",
        "c.Mode != TestNetworkLegacyEpochZero && c.Mode != TestNetworkEpochAware",
        "false",
        "TestProductionAndLegacyModes",
    ),
    (
        "builder",
        "verify.go",
        "if err = v.checkSnapshot(d, sha256.Sum256(b), s, false); err != nil",
        "if err = v.checkSnapshot(d, sha256.Sum256(b), s, false); false && err != nil",
        "TestBuilderRequiresCurrentEpochAndPolicy",
    ),
    (
        "domain",
        "delegation.go",
        "!bytes.Equal(b[:len(delegationDomain)], []byte(delegationDomain))",
        "false",
        "TestFrozenVectors/wrong-domain",
    ),
    (
        "key-canonical",
        "delegation.go",
        "!bytes.Equal(p.Bytes(), d.TransportKey[:])",
        "false",
        "TestFrozenVectors/noncanonical-key",
    ),
    (
        "key-order",
        "delegation.go",
        "new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1",
        "false",
        "TestFrozenVectors/identity-key",
    ),
    (
        "purpose-bits",
        "delegation.go",
        "d.Purposes == 0 || d.Purposes & ^Purpose(7) != 0",
        "false",
        "TestFrozenVectors/unknown-purpose",
    ),
    (
        "lifetime",
        "delegation.go",
        "d.NotBefore == 0 || d.NotAfter <= d.NotBefore || d.NotAfter-d.NotBefore > MaxDelegationSeconds",
        "false",
        "TestFrozenVectors/excessive-lifetime",
    ),
    (
        "credential-limit",
        "delegation.go",
        "d.MaxCredentialSeconds == 0 || d.MaxCredentialSeconds > MaxCredentialSeconds",
        "false",
        "TestFrozenVectors/excessive-credential",
    ),
    (
        "network",
        "chain.go",
        "state.Network.NetworkId != network.NetworkId",
        "false",
        "TestVerificationChecks/network",
    ),
    (
        "finality",
        "chain.go",
        "reference.FinalizedCheckpoint == 0",
        "false",
        "TestVerificationChecks/finality",
    ),
    (
        "minimum-checkpoint",
        "chain.go",
        "reference.FinalizedCheckpoint < policy.MinFinalizedCheckpoint",
        "false",
        "TestVerificationChecks/stale-checkpoint",
    ),
    (
        "registry",
        "chain.go",
        "!policy.AcceptsRegistry(reference.ContractCodeHash)",
        "false",
        "TestVerificationChecks/registry-code",
    ),
    (
        "account",
        "chain.go",
        "expected != reference.Account",
        "false && expected != reference.Account",
        "TestVerificationChecks/account",
    ),
    (
        "tombstone",
        "chain.go",
        "agent.Tombstoned || agent.Policy == nil",
        "agent.Policy == nil",
        "TestVerificationChecks/tombstone",
    ),
    (
        "agent",
        "chain.go",
        "agent.AgentId != agentID",
        "false",
        "TestVerificationChecks/agent",
    ),
    (
        "state-hash",
        "chain.go",
        "!chainDigestPattern.MatchString(state.TvmStateHash)",
        "false",
        "TestVerificationChecks/typed-state-hash",
    ),
    (
        "transaction-hash",
        "chain.go",
        "!chainDigestPattern.MatchString(reference.TransactionHash)",
        "false",
        "TestVerificationChecks/transaction-hash",
    ),
    (
        "membership",
        "verify.go",
        'if !found {\n\t\t\treturn errors.New("delegation is not in the finalized live set")',
        'if false && !found {\n\t\t\treturn errors.New("delegation is not in the finalized live set")',
        "TestVerificationChecks/membership",
    ),
    (
        "current-epoch",
        "verify.go",
        "d.AuthorizationEpoch != *s.CurrentEpoch",
        "false",
        "TestVerificationChecks/current-epoch",
    ),
    (
        "admission-epoch",
        "verify.go",
        "epoch != d.AuthorizationEpoch",
        "false && epoch != d.AuthorizationEpoch",
        "TestVerificationChecks/admission-epoch",
    ),
    (
        "admission-present",
        "verify.go",
        "!present || epoch != d.AuthorizationEpoch",
        "epoch != d.AuthorizationEpoch && present",
        "TestVerificationChecks/missing-admission",
    ),
    (
        "epoch-checkpoint",
        "verify.go",
        "s.State.Reference.FinalizedCheckpoint != s.EpochCheckpoint",
        "false",
        "TestVerificationChecks/mixed-checkpoints",
    ),
    (
        "policy",
        "verify.go",
        "!bytes.Equal(policy.Hash(), d.PolicyHash[:])",
        "false && !bytes.Equal(policy.Hash(), d.PolicyHash[:])",
        "TestVerificationChecks/policy",
    ),
    (
        "not-before",
        "verify.go",
        "(d.NotBefore > seconds && d.NotBefore-seconds > 300)",
        "false",
        "TestVerificationChecks/not-before",
    ),
    (
        "not-after",
        "verify.go",
        "seconds >= d.NotAfter",
        "false",
        "TestVerificationChecks/expired",
    ),
    (
        "purpose-use",
        "verify.go",
        "d.Purposes&purpose == 0",
        "false",
        "TestVerificationChecks/purpose",
    ),
    (
        "purpose-known",
        "verify.go",
        "purpose != Relay && purpose != Hints && purpose != Direct",
        "false",
        "TestVerificationChecks/unknown-purpose",
    ),
    (
        "refresh",
        "verify.go",
        "now.Sub(checked) < RefreshAfter",
        "now.Sub(checked) <= RefreshAfter",
        "TestCacheBounds",
    ),
    (
        "stale-refusal",
        "verify.go",
        "after.Sub(checked) < RefuseAfter",
        "after.Sub(checked) <= RefuseAfter",
        "TestCacheBounds",
    ),
    (
        "integrity-fallback",
        "verify.go",
        "!errors.Is(readErr, ErrUnavailable)",
        "false",
        "TestFallbackNeverHidesRevocationOrIntegrity",
    ),
    (
        "credential-size",
        "credential.go",
        "len(b) > MaxCredentialSize",
        "false",
        "TestCredentialBounds/size",
    ),
    (
        "credential-domain",
        "credential.go",
        "!bytes.Equal(b[:len(credentialDomain)], []byte(credentialDomain))",
        "false && (!bytes.Equal(b[:len(credentialDomain)], []byte(credentialDomain)))",
        "TestDecodeRefusals/domain",
    ),
    (
        "embedded-delegation",
        "credential.go",
        "if err != nil {\n\t\treturn nil, invalid(\"embedded delegation",
        "if false {\n\t\treturn nil, invalid(\"embedded delegation",
        "TestDecodeRefusals/delegation",
    ),
    (
        "block-count",
        "credential.go",
        "count < 1 || count > MaxCredentialBlocks",
        "false && (count < 1 || count > MaxCredentialBlocks)",
        "TestCredentialBounds/blocks",
    ),
    (
        "caveat-count",
        "credential.go",
        "count < 1 || count > MaxCaveatsPerBlock",
        "count > MaxCaveatsPerBlock",
        "TestDecodeRefusals/empty-later-block",
    ),
    (
        "caveat-order",
        "credential.go",
        "index > 0 && t <= b.Caveats[index-1].Type",
        "false && (index > 0 && t <= b.Caveats[index-1].Type)",
        "TestDecodeRefusals/order",
    ),
    (
        "block-length",
        "credential.go",
        "if len(rest) != 0 {\n\t\treturn b, invalid(\"block length disagrees",
        "if false {\n\t\treturn b, invalid(\"block length disagrees",
        "TestDecodeRefusals/caveat-count-short",
    ),
    (
        "credential-trailing",
        "credential.go",
        "if len(rest) != 0 {\n\t\treturn nil, invalid(\"trailing",
        "if false {\n\t\treturn nil, invalid(\"trailing",
        "TestDecodeRefusals/trailing",
    ),
    (
        "block0-caveats",
        "credential.go",
        "!okBefore || !okAfter || !okOps",
        "false && (!okBefore || !okAfter || !okOps)",
        "TestFrozenCredentialVectors/decode/block0-no-operations",
    ),
    (
        "block0-lifetime",
        "credential.go",
        "after <= before || after-before > uint64(d.MaxCredentialSeconds)",
        "false && (after <= before || after-before > uint64(d.MaxCredentialSeconds))",
        "TestCredentialBounds/lifetime",
    ),
    (
        "next-key",
        "credential.go",
        "if err := checkEd25519Key(b.NextPublicKey); err != nil",
        "if err := checkEd25519Key(b.NextPublicKey); false && err != nil",
        "TestDecodeRefusals/next-key",
    ),
    (
        "next-key-canonical",
        "credential.go",
        "!bytes.Equal(point.Bytes(), key[:])",
        "false && (!bytes.Equal(point.Bytes(), key[:]))",
        "TestFrozenCredentialVectors/decode/next-key-noncanonical",
    ),
    (
        "next-key-order",
        "credential.go",
        "new(edwards25519.Point).MultByCofactor(point).Equal(edwards25519.NewIdentityPoint()) == 1",
        "false && (new(edwards25519.Point).MultByCofactor(point).Equal(edwards25519.NewIdentityPoint()) == 1)",
        "TestFrozenCredentialVectors/decode/next-key-small-order",
    ),
    (
        "caveat-time-length",
        "credential.go",
        "len(c.Value) != 8 {\n\t\t\treturn invalid(\"time caveat",
        "false {\n\t\t\treturn invalid(\"time caveat",
        "TestCaveatValueRules/time-length",
    ),
    (
        "caveat-relay-url",
        "credential.go",
        "if err := agentpacketseal.CheckRelayURL(string(c.Value)); err != nil",
        "if err := agentpacketseal.CheckRelayURL(string(c.Value)); false && err != nil",
        "TestCaveatValueRules/relay-noncanonical",
    ),
    (
        "caveat-operations-bits",
        "credential.go",
        "Operation(binary.BigEndian.Uint16(c.Value)) & ^allOperations != 0",
        "false && (Operation(binary.BigEndian.Uint16(c.Value)) & ^allOperations != 0)",
        "TestCaveatValueRules/operations-bits",
    ),
    (
        "caveat-lane-zero",
        "credential.go",
        "bytes.Equal(c.Value, make([]byte, 16))",
        "false && (bytes.Equal(c.Value, make([]byte, 16)))",
        "TestCaveatValueRules/lane-zero",
    ),
    (
        "caveat-max-envelopes",
        "credential.go",
        "binary.BigEndian.Uint32(c.Value) == 0 {\n\t\t\treturn invalid(\"max_envelopes",
        "false {\n\t\t\treturn invalid(\"max_envelopes",
        "TestCaveatValueRules/max-envelopes-zero",
    ),
    (
        "caveat-envelope-bytes",
        "credential.go",
        "n == 0 || n > MaxEnvelopeBytes",
        "false && (n == 0 || n > MaxEnvelopeBytes)",
        "TestCaveatValueRules/envelope-bytes-over",
    ),
    (
        "caveat-lane-bytes",
        "credential.go",
        "binary.BigEndian.Uint64(c.Value) == 0",
        "false && (binary.BigEndian.Uint64(c.Value) == 0)",
        "TestCaveatValueRules/lane-bytes-zero",
    ),
    (
        "caveat-unknown-type",
        "credential.go",
        "\n\tdefault:\n\t\treturn invalid(\"unknown caveat type %d\", c.Type)",
        "\n\tdefault:\n\t\treturn nil",
        "TestCaveatValueRules/unknown-type-9",
    ),
    (
        "chain-signature",
        "credential.go",
        "!ed25519.Verify(signer[:], blockPreimage(c.chain[index], index, b), b.Signature[:])",
        "false && (!ed25519.Verify(signer[:], blockPreimage(c.chain[index], index, b), b.Signature[:]))",
        "TestChainRefusesSpliceReorderDrop/reorder",
    ),
    (
        "chain-covers-prior",
        "credential.go",
        "out := append([]byte(credentialBlockDomain), chain[:]...)",
        "out := []byte(credentialBlockDomain)",
        "TestChainRefusesSpliceReorderDrop/splice",
    ),
    (
        "chain-binds-delegation",
        "credential.go",
        "chain = append(chain, chainStep(digest[:], nil))",
        "chain = append(chain, chainStep(digest[:0], nil))",
        "TestChainRefusesSpliceReorderDrop/other-delegation",
    ),
    (
        "issuer-key",
        "credential.go",
        "signer != d.TransportKey",
        "false && (signer != d.TransportKey)",
        "TestBuilderRefusals",
    ),
    (
        "holder-key",
        "credential.go",
        "signer != c.HolderKey()",
        "false && (signer != c.HolderKey())",
        "TestBuilderRefusals",
    ),
    (
        "builder-lane",
        "credential.go",
        "if _, _, err = decoded.Lane(); err != nil",
        "if _, _, err = decoded.Lane(); false && err != nil",
        "TestBuilderRefusals",
    ),
    (
        "signing-key-length",
        "credential.go",
        "len(key) != ed25519.PrivateKeySize",
        "false && (len(key) != ed25519.PrivateKeySize)",
        "TestBuilderRefusals",
    ),
    (
        "next-key-length",
        "credential.go",
        "len(next) != ed25519.PublicKeySize {\n\t\treturn nil, invalid(\"next public key length\")\n\t}\n\tc := &Credential",
        "false {\n\t\treturn nil, invalid(\"next public key length\")\n\t}\n\tc := &Credential",
        "TestBuilderRefusals",
    ),
    (
        "scope-last-block-only",
        "credential.go",
        "for index, b := range c.Blocks {\n\t\tfor _, cv := range b.Caveats {\n\t\t\tswitch cv.Type {\n\t\t\tcase CaveatNotBefore:",
        "for index, b := range c.Blocks[len(c.Blocks)-1:] {\n\t\tfor _, cv := range b.Caveats {\n\t\t\tswitch cv.Type {\n\t\t\tcase CaveatNotBefore:",
        "TestNarrowingProperty",
    ),
    (
        "scope-first-block-only",
        "credential.go",
        "for index, b := range c.Blocks {\n\t\tfor _, cv := range b.Caveats {\n\t\t\tswitch cv.Type {\n\t\t\tcase CaveatNotBefore:",
        "for index, b := range c.Blocks[:1] {\n\t\tfor _, cv := range b.Caveats {\n\t\t\tswitch cv.Type {\n\t\t\tcase CaveatNotBefore:",
        "TestNarrowingProperty",
    ),
    (
        "scope-merged-last-value",
        "credential.go",
        "for index, b := range c.Blocks {\n\t\tfor _, cv := range b.Caveats {\n\t\t\tswitch cv.Type {\n\t\t\tcase CaveatNotBefore:",
        "for index, b := range c.Blocks {\n\t\tfor _, cv := range b.Caveats {\n\t\t\tif func() bool {\n\t\t\t\tfor _, later := range c.Blocks[index+1:] {\n\t\t\t\t\tif _, ok := findCaveat(later, cv.Type); ok {\n\t\t\t\t\t\treturn true\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t\treturn false\n\t\t\t}() {\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\tswitch cv.Type {\n\t\t\tcase CaveatNotBefore:",
        "TestNarrowingProperty",
    ),
    (
        "deposit-last-block-only",
        "credential.go",
        "for index, b := range c.Blocks {\n\t\tfor _, cv := range b.Caveats {\n\t\t\tswitch cv.Type {\n\t\t\tcase CaveatMaxEnvelopes:",
        "for index, b := range c.Blocks[len(c.Blocks)-1:] {\n\t\tfor _, cv := range b.Caveats {\n\t\t\tswitch cv.Type {\n\t\t\tcase CaveatMaxEnvelopes:",
        "TestNarrowingProperty",
    ),
    (
        "deposit-merged-last-value",
        "credential.go",
        "for index, b := range c.Blocks {\n\t\tfor _, cv := range b.Caveats {\n\t\t\tswitch cv.Type {\n\t\t\tcase CaveatMaxEnvelopes:",
        "for index, b := range c.Blocks {\n\t\tfor _, cv := range b.Caveats {\n\t\t\tif func() bool {\n\t\t\t\tfor _, later := range c.Blocks[index+1:] {\n\t\t\t\t\tif _, ok := findCaveat(later, cv.Type); ok {\n\t\t\t\t\t\treturn true\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t\treturn false\n\t\t\t}() {\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\tswitch cv.Type {\n\t\t\tcase CaveatMaxEnvelopes:",
        "TestNarrowingProperty",
    ),
    (
        "scope-not-before",
        "credential.go",
        "nb > now && nb-now > ClockSkewSeconds",
        "false && (nb > now && nb-now > ClockSkewSeconds)",
        "TestScopeEveryBlock/not-before",
    ),
    (
        "scope-not-after",
        "credential.go",
        "if now >= decodeU64(cv)",
        "if false",
        "TestScopeEveryBlock/not-after",
    ),
    (
        "scope-relay",
        "credential.go",
        "string(cv.Value) != relayURL",
        "false && (string(cv.Value) != relayURL)",
        "TestScopeEveryBlock/relay",
    ),
    (
        "scope-operations",
        "credential.go",
        "Operation(binary.BigEndian.Uint16(cv.Value))&op == 0",
        "false && (Operation(binary.BigEndian.Uint16(cv.Value))&op == 0)",
        "TestScopeEveryBlock/operation",
    ),
    (
        "scope-single-operation",
        "credential.go",
        "if err := checkOperation(op); err != nil",
        "if err := checkOperation(op); false && err != nil",
        "TestScopeEveryBlock/composite-operation",
    ),
    (
        "scope-zero-time",
        "credential.go",
        "if now == 0",
        "if false",
        "TestScopeEveryBlock/zero-time",
    ),
    (
        "scope-lane-conflict",
        "credential.go",
        "if _, _, err := c.Lane(); err != nil",
        "if _, _, err := c.Lane(); false && err != nil",
        "TestScopeEveryBlock/lane-conflict",
    ),
    (
        "lane-conflict",
        "credential.go",
        "explicit && !bytes.Equal(lane[:], v.Value)",
        "false && (explicit && !bytes.Equal(lane[:], v.Value))",
        "TestScopeEveryBlock/lane-conflict",
    ),
    (
        "deposit-max-envelopes",
        "credential.go",
        "u.StoredEnvelopes >= uint64(binary.BigEndian.Uint32(cv.Value))",
        "false && (u.StoredEnvelopes >= uint64(binary.BigEndian.Uint32(cv.Value)))",
        "TestDepositEveryBlock/envelopes",
    ),
    (
        "deposit-envelope-bytes",
        "credential.go",
        "u.EnvelopeBytes > uint64(binary.BigEndian.Uint32(cv.Value))",
        "false && (u.EnvelopeBytes > uint64(binary.BigEndian.Uint32(cv.Value)))",
        "TestDepositEveryBlock/envelope-bytes",
    ),
    (
        "deposit-lane-bytes",
        "credential.go",
        "overflow || total > decodeU64(cv)",
        "false && (overflow || total > decodeU64(cv))",
        "TestDepositEveryBlock/lane-bytes",
    ),
    (
        "deposit-lane-overflow",
        "credential.go",
        "overflow || total > decodeU64(cv)",
        "(overflow && false) || total > decodeU64(cv)",
        "TestDepositEveryBlock/lane-bytes-overflow",
    ),
    (
        "deposit-contact-cap",
        "credential.go",
        "u.StoredEnvelopes >= MaxContactLaneEnvelopes",
        "false && (u.StoredEnvelopes >= MaxContactLaneEnvelopes)",
        "TestDepositEveryBlock/contact-lane-cap",
    ),
    (
        "deposit-envelope-range",
        "credential.go",
        "u.EnvelopeBytes == 0 || u.EnvelopeBytes > MaxEnvelopeBytes",
        "false && (u.EnvelopeBytes == 0 || u.EnvelopeBytes > MaxEnvelopeBytes)",
        "TestDepositEveryBlock/empty-envelope",
    ),
    (
        "proof-relay-url",
        "proof.go",
        "if err := (Caveat{Type: CaveatRelay, Value: []byte(r.RelayURL)}).validate(); err != nil",
        "if err := (Caveat{Type: CaveatRelay, Value: []byte(r.RelayURL)}).validate(); false && err != nil",
        "TestProofInputRules/relay-noncanonical",
    ),
    (
        "proof-method-length",
        "proof.go",
        "len(r.Method) < 1 || len(r.Method) > maxMethod",
        "false && (len(r.Method) < 1 || len(r.Method) > maxMethod)",
        "TestProofInputRules/method-long",
    ),
    (
        "proof-method-token",
        "proof.go",
        "r.Method[i] < 'A' || r.Method[i] > 'Z'",
        "false && (r.Method[i] < 'A' || r.Method[i] > 'Z')",
        "TestProofInputRules/method-lowercase",
    ),
    (
        "proof-path-shape",
        "proof.go",
        "len(r.Path) < 1 || len(r.Path) > maxPathSize || r.Path[0] != '/'",
        "len(r.Path) < 1",
        "TestProofInputRules/path-relative",
    ),
    (
        "proof-path-bytes",
        "proof.go",
        "c <= 0x20 || c >= 0x7f || c == '?' || c == '#'",
        "false && (c <= 0x20 || c >= 0x7f || c == '?' || c == '#')",
        "TestProofInputRules/path-query",
    ),
    (
        "header-canonical",
        "proof.go",
        "err != nil || rawURL.EncodeToString(raw) != value",
        "err != nil",
        "TestRequestProof/line-break",
    ),
    (
        "header-limit",
        "proof.go",
        "len(value) > limit",
        "false && (len(value) > limit)",
        "TestProofHeaderBounds",
    ),
    (
        "proof-length",
        "proof.go",
        "len(raw) != ProofHeaderSize",
        "false && (len(raw) != ProofHeaderSize)",
        "TestProofInputRules/short-proof",
    ),
    (
        "proof-window",
        "proof.go",
        "if err := CheckProofWindow(p.IssuedAt, now); err != nil {\n\t\treturn err\n\t}\n\tpreimage",
        "if err := CheckProofWindow(p.IssuedAt, now); false && err != nil {\n\t\treturn err\n\t}\n\tpreimage",
        "TestRequestProof/window-ahead",
    ),
    (
        "proof-window-ahead",
        "proof.go",
        "(issuedAt > now && issuedAt-now > ProofWindowSeconds)",
        "false && ((issuedAt > now && issuedAt-now > ProofWindowSeconds))",
        "TestRequestProof/window-ahead",
    ),
    (
        "proof-window-behind",
        "proof.go",
        "(now > issuedAt && now-issuedAt > ProofWindowSeconds)",
        "false && ((now > issuedAt && now-issuedAt > ProofWindowSeconds))",
        "TestRequestProof/window-behind",
    ),
    (
        "proof-signature",
        "proof.go",
        "!ed25519.Verify(holder[:], preimage, p.Signature[:])",
        "false && (!ed25519.Verify(holder[:], preimage, p.Signature[:]))",
        "TestRequestProof/signature",
    ),
    (
        "proof-holder",
        "proof.go",
        "public != c.HolderKey()",
        "false && (public != c.HolderKey())",
        "TestRequestProof",
    ),
    (
        "request-agent",
        "proof.go",
        "c.Delegation.AgentID() != r.AgentID",
        "false && (c.Delegation.AgentID() != r.AgentID)",
        "TestRequestProof/agent",
    ),
    (
        "request-chain",
        "proof.go",
        "if err = c.VerifyChain(); err != nil",
        "if err = c.VerifyChain(); false && err != nil",
        "TestRequestProof/chain",
    ),
    (
        "request-scope",
        "proof.go",
        "if err = c.CheckScope(r.Now, r.Proof.RelayURL, r.Operation); err != nil",
        "if err = c.CheckScope(r.Now, r.Proof.RelayURL, r.Operation); false && err != nil",
        "TestRequestProof/operation",
    ),
    (
        "replay-duplicate",
        "replay.go",
        "if _, seen := t.live[key]; seen",
        "if _, seen := t.live[key]; false && seen",
        "TestReplayClaimOnce",
    ),
    (
        "replay-window",
        "replay.go",
        "if err := CheckProofWindow(p.IssuedAt, now); err != nil",
        "if err := CheckProofWindow(p.IssuedAt, now); false && err != nil",
        "TestReplayClaimOnce",
    ),
    (
        "replay-full",
        "replay.go",
        "len(t.live) >= t.config.Entries",
        "false && (len(t.live) >= t.config.Entries)",
        "TestReplayTableFailsClosedWhenFull",
    ),
    (
        "replay-per-credential",
        "replay.go",
        "t.counts[credentialID] >= t.config.PerCredential",
        "false && (t.counts[credentialID] >= t.config.PerCredential)",
        "TestReplayPerCredentialBound",
    ),
    (
        "replay-per-credential-config",
        "replay.go",
        "c.PerCredential > MaxReplayPerCredential",
        "false && (c.PerCredential > MaxReplayPerCredential)",
        "TestReplayPerCredentialBound",
    ),
    (
        "replay-evicts-at-edge",
        "replay.go",
        "now-t.byTime[0].issuedAt > ProofWindowSeconds",
        "now-t.byTime[0].issuedAt >= ProofWindowSeconds",
        "TestReplayNeverEvictsInWindow",
    ),
    (
        "replay-floor-raise",
        "replay.go",
        "t.floor = max(t.floor, e.issuedAt)",
        "_ = e.issuedAt",
        "TestReplayFloorAfterClockRollback",
    ),
    (
        "replay-floor",
        "replay.go",
        "if p.IssuedAt <= t.floor",
        "if false",
        "TestReplayFloorAfterClockRollback",
    ),
    (
        "replay-mark",
        "replay.go",
        "if p.IssuedAt >= t.mark",
        "if false",
        "TestHighWaterMark",
    ),
    (
        "mark-never-decreases",
        "replay.go",
        "return max(t.mark, lead)",
        "return lead",
        "TestHighWaterMark",
    ),
    (
        "mark-record-decrease",
        "replay.go",
        "mark < t.mark || mark == 0",
        "mark == 0",
        "TestHighWaterMark",
    ),
    (
        "mark-overflow",
        "replay.go",
        "if lead < now",
        "if false",
        "TestHighWaterMark",
    ),
    (
        "restore-floor",
        "replay.go",
        "t.floor, t.mark = recordedMark, recordedMark",
        "t.mark = recordedMark",
        "TestRestartRefusesAdmittedProofs",
    ),
    (
        "restore-needs-mark",
        "replay.go",
        "if recordedMark == 0",
        "if false",
        "TestRestartRefusesAdmittedProofs",
    ),
    (
        "mark-refusal-class",
        "replay.go",
        "fmt.Errorf(\"%w: proof time is not below the recorded high-water mark\", ErrReplayTableFull)",
        "errors.New(\"proof time is not below the recorded high-water mark\")",
        "TestHighWaterMark",
    ),
]


def execute(args):
    result = subprocess.run(
        args,
        check=False,
        cwd=ROOT,
        env={**os.environ, "GOWORK": "off", "GOFLAGS": "-p=2"},
        capture_output=True,
        text=True,
        timeout=180,
    )
    return result.returncode, result.stdout + result.stderr


def main():
    code, output = execute(["go", "test", "-count=1", PACKAGE])
    if code:
        raise RuntimeError("baseline failed\n" + output)
    for name, filename, old, new, test in MUTANTS:
        source = ROOT / "protocol/pkg/agenttransport" / filename
        original = source.read_text()
        if original.count(old) != 1:
            raise RuntimeError("non-unique anchor: " + name)
        with tempfile.TemporaryDirectory(prefix="agenttransport-mutant-") as tmp:
            replacement = Path(tmp) / filename
            replacement.write_text(original.replace(old, new))
            overlay = Path(tmp) / "overlay.json"
            overlay.write_text(json.dumps({"Replace": {str(source): str(replacement)}}))
            code, output = execute(
                [
                    "go",
                    "test",
                    "-vet=off",
                    "-count=1",
                    "-overlay",
                    str(overlay),
                    "-run",
                    "^" + test + "$",
                    PACKAGE,
                ]
            )
        # Subtests indent their marker; require the exact named failure, never
        # a compiler error, timeout, missing test or unrelated failing test.
        if code == 0 or "--- FAIL: " + test not in output or "[build failed]" in output:
            raise RuntimeError(
                "mutant did not fail its named test: " + name + "\n" + output
            )
        if name in {"verifier-network-allowlist", "resolver-network-allowlist"}:
            # Prove each requested identity/mode refusal went red, rather than
            # accepting one failing sibling as evidence for the whole matrix.
            for identity in ("production-identity", "unknown-identity"):
                for mode in (
                    "test-network-legacy-epoch-zero",
                    "test-network-epoch-aware",
                ):
                    case = test + "/" + identity + "/" + mode
                    if "--- FAIL: " + case not in output:
                        raise RuntimeError(
                            "identity/mode control stayed green: "
                            + case
                            + "\n"
                            + output
                        )
                    print("RED identity/mode: " + case, flush=True)
        print("RED " + name + ": " + test, flush=True)
    print(f"AGENTTRANSPORT_MUTANTS_OK: {len(MUTANTS)} checks removed and caught")


if __name__ == "__main__":
    main()
