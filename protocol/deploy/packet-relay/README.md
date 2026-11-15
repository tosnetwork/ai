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
| `-max-concurrent-deposits` | 256 | deposit bodies in memory at once; past it `503` |
| `-sweep-interval` | 1m | expiry sweep |

A client address is the IP address, IPv6 aggregated to its /64. A full
mailbox or a full relay answers `507`; nothing is ever evicted. When a rate
table is full of clients that are all still being limited, a new client is
answered `429` rather than evicting one of them.

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
no request bodies, paths, Agent IDs or client addresses.

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
