# Accepted Quote TVM Cell V1

## Canonical boundary

A Quote Proposal is gateway-local and non-canonical. The client converts one
proposal into the cell below. Its TVM cell hash is the Accepted Quote
commitment. `proposal_id` is deliberately excluded, so gateways cannot become
part of canonical commercial identity.

The cell settles on the Service Actor rail
([`SERVICE_ACTOR_TVM_V1.md`](SERVICE_ACTOR_TVM_V1.md); binding rules in
[`SERVICE_ACTOR_SETTLEMENT_DESIGN.md`](SERVICE_ACTOR_SETTLEMENT_DESIGN.md)
sections 2-3). It is not itself stored on chain. The buyer commits to it through
the `request_hash` of a `call` (section "Request commitment"), and the
finalized successful `call` transaction is the acceptance event. Schema 1 is
this layout; the earlier stablecoin-escrow layout of schema 1 and the Paid
Demand schema 2 are retired and not accepted by any conforming tool. Schema 3
is the token-rail layout (section "Schema 3: the token rail"); schema 2 is not
reused.

## Cell layout

```text
accepted_quote$_ magic:uint32=0x4e415131 schema:uint16=1
  ^network_domain ^identity ^rail ^authority = AcceptedQuoteV1;

network_domain$_ genesis_root:uint256 genesis_file:uint256
  network_id_sha256:uint256 = NetworkDomainV1;

identity$_ capability_id:uint256 provider_agent_id:uint256
  ^version = QuoteIdentityV1;

version$_ capability_version_sha256:uint256 manifest_digest:uint256
  transport_binding_digest:uint256 expires_at:uint64
  ^capability_version_snake = QuoteVersionV1;

rail$_ actor:MsgAddressInt actor_code_hash:uint256 policy_version:uint32
  ^rail_terms = QuoteRailV1;                                -- 555 bits

rail_terms$_ terms_hash:uint256 price:Coins storage_fee:Coins
  = QuoteRailTermsV1;                                       -- <= 504 bits

authority$_ attestor_key_id:uint256 = QuoteAuthorityV1;

transport_binding$_ magic:uint32=0x4e544231 schema:uint16=1
  security_mode:uint8 max_request_bytes:uint32
  ^base_url_snake = NativeTransportBindingV1;
```

The rail is split across two cells because one cell would need 1,059 bits; the
Quote keeps the contract's full Coins bound instead of a narrower one
(design section 3.1).

- `actor` is a canonical `addr_std` on workchain 0 with no anycast. It equals
  manifest key 21 and the destination of the `call`.
- `actor_code_hash` equals manifest key 21, the account's code hash and a
  published Service Actor release (pending: no release is published yet, so no
  Quote can currently be verified).
- `policy_version`, `terms_hash`, `price` and `storage_fee` equal the decoded
  current actor policy at quote time; `terms_hash` is computed as
  `SERVICE_ACTOR_TVM_V1.md` section 5 defines it. `price` is the exact
  `price_per_call` in nanoTOS, below `2^120` and non-zero; `storage_fee` is
  non-refundable and the Quote must disclose it as such (D4).
- `attestor_key_id` is the ML-DSA-44 key id that manifest key 21 names and that
  `terms_hash` covers; its text form is `mldsa44:<64 lowercase hex>`.
- `expires_at` is a buyer-side acceptance deadline only: a buyer refuses to
  `call` at or after it. The contract does not see it; a stale quote fails
  closed through `terms_hash` (D7).
- In schema 1 the asset is native TOS and has no field: the native rail
  settles nothing else (D8). A token-rail Quote uses schema 3.
- The dispute policy is fixed by contract code: an attested response pays,
  otherwise the price returns to the caller (design section 3.3). There is no
  dispute-policy digest.

Strings are printable ASCII, minimally encoded as byte-aligned TVM snakes.

The transport digest is `cell_hash(transport_binding)`. Security mode `0` is
Connect RPC over plaintext HTTP and is permitted only for an explicit loopback
bootstrap endpoint; mode `1` is Connect RPC over HTTPS. For modes `0` and `1`
the base URL is a canonical absolute ASCII URL with no credentials, query,
fragment, or trailing slash. It may carry a path prefix of `/`-separated
non-empty segments of RFC 3986 unreserved characters (`A-Z a-z 0-9 - . _ ~`),
with no `.` or `..` segment and no percent-escape, for example
`https://provider.example/tos/rpc`. The service is fixed by this schema to
`tos.service.v1.NativeService`; it is not supplied by a gateway.

Mode `2` is Agent Packet V1 (`AGENT_PACKET_V1.md`) carried by the Messenger to
the Capability owner Agent. There is no HTTP endpoint and no Connect service:
the base URL is exactly `agent-packet:agent_<64 lowercase hex>` (83 bytes) and
must name the Quote's `provider_agent_id`; a Quote whose mode-2 base URL names
any other Agent is invalid. `max_request_bytes` is the inline work input a
buyer may deliver, at most 1 MiB for mode `2`; the input travels as a sequence
of signed Agent Packets, each within the Messenger event bound, and a buyer
refuses larger input before `call`. No upload reference is defined.

In every mode the base URL is at most 120 bytes and occupies one canonical
cell without continuation references, and `max_request_bytes` is non-zero and
at most 16 MiB. A production Quote must use mode `1` or mode `2`. The layout and
schema are unchanged by mode `2`, so mode `0` and `1` bindings keep their
digests. Frozen encodings of every mode and refused shapes are in
`test-vectors/transport-binding-v1.json`, generated by the protocol
implementation; `python3 -I scripts/reproduce-transport-binding-v1.py`
recomputes every digest and rule independently.

## Schema 3: the token rail

A Quote for a token-rail Service Actor
([`SERVICE_ACTOR_TOKEN_TVM_V1.md`](SERVICE_ACTOR_TOKEN_TVM_V1.md)) uses schema 3.
The network domain, identity, version, authority and transport binding cells
are those of schema 1; only the rail changes:

```text
accepted_quote$_ magic:uint32=0x4e415131 schema:uint16=3
  ^network_domain ^identity ^rail ^authority = AcceptedQuoteTokenV1;

rail$_ actor:MsgAddressInt actor_code_hash:uint256 policy_version:uint32
  ^rail_terms ^asset = QuoteTokenRailV1;                    -- 555 bits

rail_terms$_ terms_hash:uint256 price_atomic:Coins storage_fee:Coins
  = QuoteTokenRailTermsV1;                                  -- <= 504 bits

asset$_ master:MsgAddressInt minter_code_hash:uint256
  wallet_code_hash:uint256 decimals:uint8 = QuoteAssetV1;   -- 787 bits
```

- `actor`, `actor_code_hash` and `policy_version` are as in schema 1, except
  that `actor_code_hash` equals the token-rail release
  (`tos-service-actor-token-v1`) and manifest key 21 field 4.
- `terms_hash` is the token terms hash (`SERVICE_ACTOR_TOKEN_TVM_V1.md` section
  5), which binds the asset master and wallet code hash.
- `price_atomic` is the actor's exact `price_per_call` in the asset's atomic
  units, non-zero and below `2^120`; `storage_fee` is nanoTOS and
  non-refundable, as in schema 1.
- `asset.master` is a canonical `addr_std` on workchain 0 with no anycast and
  equals the actor's route master; `wallet_code_hash` equals the route's;
  `minter_code_hash` and `decimals` equal the pinned ConfigParam 84 record with
  status 1 at the quote's checkpoint, and the whole cell equals manifest key 20
  and the Quote Proposal's `asset`.
- `ServiceRequestV1` is unchanged: it commits to `quote_commitment`, which now
  binds the asset.
- A decoder refuses schema 3 with a native-rail `actor_code_hash`, schema 1
  with a token-rail one, a missing `^asset`, and trailing bits or references in
  any cell.

**Status.** Specified only. Its production encoder, its vectors (generated
from the token actor's execution vectors and reproduced independently) and its
negative cases are T7 work (`USDC_SETTLEMENT_V1.md` section 8). No tool
accepts schema 3 until they exist.

## Manifest, version and provider

The manifest digest is the digest of the canonical software-work manifest.
The exact Capability version in finalized Registry state must bind the same
digest and must be non-revoked when the buyer calls. The provider must be the
finalized Capability owner.

## Request commitment

```text
quote_commitment = cell_hash(accepted_quote)
request_hash     = cell_hash(service_request)
service_request$_ magic:uint32=0x4e535231 schema:uint16=1
  quote_commitment:uint256 execution_id:uint256 input_digest:uint256
  = ServiceRequestV1;
```

`magic` is ASCII `NSR1`. Every field is non-zero. The `call` carries
`request_hash` and `expected_terms_hash = rail_terms.terms_hash`; buyer tooling
always passes the quoted value, never the actor's live terms. A buyer never
reuses a `request_hash`.

## Verification rule

Before building a `call`, the buyer runs admission-time verification, and a
resolver attributes an existing request only after existing-request
verification, both as `SERVICE_ACTOR_SETTLEMENT_DESIGN.md` section 2.4
specifies, from one quorum-finalized checkpoint. Any absent, ambiguous or
mismatched authoritative value is a verification error.

## Vectors

Pending. The frozen [`accepted-quote-v1.json`](../test-vectors/accepted-quote-v1.json)
and `accepted-quote-v1-2.json` encode the retired stablecoin-escrow layout and
are not conformance vectors for this cell. Vectors for this layout,
`ServiceRequestV1` and `terms_hash` must be generated from the changed contract
and reproduced by the production and an independent encoder before this cell
is frozen.
