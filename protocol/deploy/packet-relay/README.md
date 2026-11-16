# Agent Packet Relay deployment

`tos-service-packet-relay` is an [Agent Packet Relay V1](../../../spec/docs/AGENT_PACKET_RELAY_V1.md)
mailbox: a bounded, durable store of end-to-end-encrypted envelopes keyed by
recipient Agent ID. It has no authority. It never decrypts, holds no key,
signs nothing and needs no chain RPC; losing it, or its state directory,
changes availability only.

## Build

```bash
GOWORK=off go build -trimpath -o tos-service-packet-relay ./protocol/cmd/tos-service-packet-relay
```

## Transport

The relay base URL that recipients publish in their key cards must be
`https://`. Two deployments are supported:

- **Direct TLS (recommended).** `-tls-cert` and `-tls-key` serve HTTPS on
  `-listen`. The client address used for quotas and rate limits is the TCP
  peer. The supplied unit does this on port 443.
- **Behind a TLS-terminating proxy on the same host.** Without a certificate
  the relay serves plain HTTP and refuses any listen address that is not
  loopback (`127.0.0.1`, `::1`, `localhost`). Set
  `-trusted-proxy 127.0.0.1` (repeatable; an address or CIDR prefix) so the
  relay believes that proxy's `X-Forwarded-For`: the header is walked from
  the right and the first address that is not a trusted proxy is the client.
  Without `-trusted-proxy` the header is ignored, so behind a proxy every
  request would count as the proxy's own address. Connection bounds are
  applied when a connection is accepted, when only the TCP peer is known:
  a trusted proxy's connections count only against `-max-connections`, so
  the proxy must bound each of its own clients' connections and keep-alive
  time itself. The proxy must not buffer
  unbounded bodies, must pass status codes and `Retry-After` through
  unchanged, must not follow or add redirects, and must not log request
  bodies.

A base path is supported with `-base-path /relay` (the key card then names
`https://host/relay`).

## Limits

| Flag | Default | V1 bound |
|---|---|---|
| `-global-max-entries` | none, required | envelopes plus tombstones |
| `-global-max-bytes` | none, required | stored envelope bytes |
| `-per-recipient-max-envelopes` | 256 | at most 256 |
| `-per-recipient-max-bytes` | 16777216 | at most 16 MiB |
| `-per-client-recipient-max-envelopes` | 64 | at most 64 |
| `-ttl` | 24h | at most 24 h, whole seconds |
| `-deposit-rate-per-minute`, `-deposit-burst` | 60, 32 | per client address |
| `-read-rate-per-minute`, `-read-burst` | 600, 100 | list, download, ack per client address |
| `-max-rate-clients` | 65536 | addresses tracked per rate table |
| `-max-connections` | 1024 | concurrent connections; past it a new connection is closed at once |
| `-max-connections-per-client` | 16 | concurrent connections per TCP peer address (IPv6 per /64); trusted proxies exempt |
| `-max-connections-per-48` | 64 | concurrent connections of all peers in one IPv6 /48; trusted proxies exempt |
| `-max-concurrent-deposits` | 256 | deposit bodies in memory at once; past it `503` |
| `-max-concurrent-deposits-per-client` | 4 | deposit bodies one client address holds at once; past it `429` |
| `-max-concurrent-deposits-per-48` | 16 | deposit bodies all clients in one IPv6 /48 hold at once; past it `429` |
| `-sweep-interval` | 1m | expiry sweep |

The shares must satisfy per client ≤ per /48 ≤ total; a share left unset
takes its default, lowered to the total when the total is smaller.

`-ttl` is set per environment: the project's test relays run `-ttl 1h`, its
production relays `-ttl 3h`. The relay advertises it as `max_ttl_seconds` in
`GET /v1/relay`, and clients re-deposit unacknowledged envelopes at 80 % of
the smallest value among a card's relays
(`spec/docs/AGENT_PACKET_RELAY_V1.md` sections 9.6 and 10), so a value below
24 h is safe only for clients that do so.

A deposit body must arrive within 5 s plus its declared length at
32 KiB/s (13 s for a maximal 256 KiB envelope); a slower body is answered
`408` (the sender retries) and frees its slot.

With the defaults, one IPv6 /48 holds at most 64 connections and 16
deposit bodies. Taking every connection then needs 16 distinct /48s or 64
IPv4 addresses (or a mix), and taking every deposit body needs 16 /48s or
64 IPv4 addresses as well. IPv4 addresses are not grouped further.

A client address is the IP address, IPv6 aggregated to its /64. A full
mailbox or a full relay answers `507`; no envelope is ever evicted. A full
rate table evicts its least recently used bucket to admit a new client;
within one IPv6 /48 at most 256 /64s get their own bucket and the rest of
that /48 shares one.

## State directory

`-state-dir` must be an absolute path on a local file system with POSIX
rename and fsync semantics. It holds `FORMAT`, `LOCK`, `envelopes/`,
`tombstones/` and `tmp/`. Every write goes to `tmp/`, is synced, renamed into
place and its directory synced before the relay answers `201` or `204`. One
process at a time may hold the directory (an advisory lock); a second start
fails.

On start the relay removes partial writes, expired entries, and any envelope
whose tombstone survived a crash between the two steps of an
acknowledgement. It refuses to start on a record that fails its checksum, an
unknown file, or an unknown `FORMAT`: move the directory aside and start
empty (pending envelopes are then lost to this relay; senders' redelivery
and the recipient's other relays recover them).

Each stored envelope record keeps the depositing client address (for the
per-(client, recipient) quota across restarts). Nothing else about a client
is stored, and the relay logs only start-up and persistence failures:
no request bodies, paths, Agent IDs or client addresses. The optional
metrics (below) carry none of these either.

## Install with systemd

```bash
install -m 0755 tos-service-packet-relay /usr/local/bin/tos-service-packet-relay
install -d -m 0700 /etc/tos-service/packet-relay
install -m 0600 fullchain.pem /etc/tos-service/packet-relay/tls-cert.pem
install -m 0600 privkey.pem /etc/tos-service/packet-relay/tls-key.pem
install -m 0644 protocol/deploy/packet-relay/tos-service-packet-relay.service \
  /etc/systemd/system/tos-service-packet-relay.service
systemctl daemon-reload
systemctl enable --now tos-service-packet-relay.service
```

Edit the global limits in the unit to the disk you give the state directory
before enabling it. The unit runs as a dynamic user with only
`CAP_NET_BIND_SERVICE`, reads its certificate through systemd credentials,
and can write nothing but its state directory.

Check it:

```bash
curl -fsS https://relay.example/v1/relay
```

which answers the advisory `tos.service.agent-packet-relay.relay.v1`
description.

## Metrics

Off by default. `-metrics-listen 127.0.0.1:9095` (or `[::1]:9095`,
`localhost:9095`) opens a second, plain-HTTP listener that serves only
`GET /metrics` in the Prometheus text exposition format. The relay refuses
to start if the address is not loopback or has no port (`0.0.0.0:9095`,
`:9095` or a public address are refused), and checks again that the address
it bound is loopback. The listener holds at most 4 connections with 5 s
timeouts; it is separate from the relay listener, which never serves
`/metrics`.

**Privacy rule.** No series carries an Agent ID, envelope ID, client
address, prefix or any other per-request value. The only labels are fixed
enums: `route` (`deposit`, `list`, `download`, `ack`, `relay` for
`GET /v1/relay`, `other` for an unknown path or method), `code` (the status
the relay answered, or `other`), and `bound` (`global`, `client`, `per48`).
The counters are a fixed set that does not grow with traffic or clients.
Every series is present, at zero, from the first scrape.

| Series | Type | Meaning |
|---|---|---|
| `packet_relay_requests_total{route,code}` | counter | answers by route class and status: `200`, `201`, `204`, `400`, `403`, `404`, `405`, `408`, `409`, `410`, `413`, `422`, `429`, `503`, `507`, `other` |
| `packet_relay_connections_refused_total{bound}` | counter | connections closed at accept by `-max-connections`, `-max-connections-per-client` or `-max-connections-per-48` |
| `packet_relay_deposit_bytes_total` | counter | envelope bytes of deposits answered `201` |
| `packet_relay_store_failures_total` | counter | `503` answers after a logged `relay store failure` |
| `packet_relay_sweep_failures_total` | counter | failed expiry sweeps (each also logged) |
| `packet_relay_open_connections` | gauge | connections the relay listener holds |
| `packet_relay_stored_envelopes`, `_stored_tombstones`, `_stored_entries`, `_stored_bytes` | gauge | the store's own accounting; a scrape never reads the disk |
| `packet_relay_global_max_entries`, `_global_max_bytes` | gauge | the configured global limits, for usage ratios |

If the metrics listener stops serving with an error, the whole relay stops
too. This fail-stop is on purpose: systemd restarts the relay rather than
leaving one running whose refusals nobody can see. On shutdown both
listeners are drained.

Counters restart from zero when the process restarts. Requests the HTTP
server rejects before the relay handler sees them (a malformed request
line, oversized headers) are not counted.

The supplied unit does not enable metrics. To enable them, add
`-metrics-listen 127.0.0.1:9095` to `ExecStart`; the unit's
`RestrictAddressFamilies` already allows loopback. Scrape on the host with
a local agent, or from an operator machine through an SSH tunnel:

```bash
ssh -N -L 9095:127.0.0.1:9095 relay.example &
curl -fsS http://127.0.0.1:9095/metrics
```

Do not expose the port through a proxy or firewall rule.
