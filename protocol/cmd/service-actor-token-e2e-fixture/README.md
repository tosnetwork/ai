# Local token deployment fixture

This unsigned fixture builder uses `nativecore` for the initial token actor
state and funding-transfer bodies. It neither signs nor broadcasts. It is a
local test tool, not an offer publisher or a buyer.

Build from the module root:

```sh
go build ./protocol/cmd/service-actor-token-e2e-fixture
```

The default operation reads one JSON object from stdin: `owner`, `master`,
`wallet_code_boc`, `actor_code_boc`, `price_atomic`, `max_liability_atomic`
and `metadata_hash`. The code must be the pinned test-profile token actor.
The result contains its address, StateInit/data BOCs and own token-wallet
address. This profile uses 600-second response and refund windows.

`funding` reads `query_id`, `amount_atomic`, `forward_nanotos`, `actor`,
`response`, `request_hash` and `terms_hash`. It returns the shared SDK's
funding-transfer body. It deliberately permits positive but underfunded
forwards and stale terms for on-chain refusal tests. Normal purchases use
the buyer SDK's admission checks instead.

Tests require `TOS_SERVICE_TOKEN_CLI_REPO` to name the pinned contract checkout,
whose test-profile artifact is independently hash-checked. Missing artifacts
are errors, never skips:

```sh
TOS_SERVICE_TOKEN_CLI_REPO="$TOS_ROOT" \
  go test ./protocol/cmd/service-actor-token-e2e-fixture
```

`transaction` takes `actor`, `lt`, `hash` and a public transaction `boc`. It
uses the finalized-reader decoder and refuses an account/LT/hash mismatch.
The caller must anchor the supplied cell to an independently read checkpoint.
The frozen public recovery receipt tests all three identity checks.

The small frozen recovery receipt is from the existing local global-id-3 chain
(genesis root `65735247a371030abe811aeac0afe357301ce90e161450d26f88b4beb5b4c366`),
with the pinned test actor. It is a public transaction cell, not a signed
spending envelope or a secret. The account, LT and representation hash are
part of the fixture; each is independently checked before its outcome is used.
