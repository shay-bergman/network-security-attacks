# DNS Cache Poisoning

*Kaminsky-style cache poisoning against a recursive resolver.*

## Overview

Two cooperating tools poison a recursive resolver's cache so it trusts an
attacker-controlled name server as authoritative for a victim zone:

- `auth_server` — the attacker's authoritative name server.
- `poison_client` — the attack client that drives the poisoning race.

## How it works

1. The client sends a trigger query to the resolver for a name in the
   attacker's own zone. The resolver recurses to `auth_server`, which records
   the resolver's UDP source port.
2. The client fetches that port from `auth_server` over a small TCP control
   channel.
3. For each round the client queries the resolver for a fresh, non-cached
   subdomain of the victim zone. While that query is outstanding it floods the
   resolver with spoofed responses forged from the root server's address,
   iterating over the full 16-bit transaction-ID space. A spoofed response
   whose transaction ID matches the resolver's outstanding query is accepted
   and installs a forged NS delegation for the victim zone, pointing at the
   attacker's name server.

Spoofed responses are injected with a raw IPv4/UDP socket (`IP_HDRINCL`) and
fully computed IP and UDP checksums. `auth_server` answers the victim host with
a poisoned A record and every other name with an empty authoritative response.

Source layout:

| File | Role |
| --- | --- |
| `lab_config.h` | Shared lab addresses, zone names, and ports. |
| `net_util.{c,h}` | IPv4 parsing and socket-option helpers. |
| `control_channel.{c,h}` | Both ends of the TCP port-sharing channel. |
| `raw_packet.{c,h}` | IPv4/UDP framing, checksums, raw socket setup. |
| `spoof_dns.{c,h}` | Client-side DNS query and spoofed-response construction. |
| `poison_client.c` | Client driver and the per-round flooding loop. |
| `dns_responder.{c,h}` | Server DNS socket, response builders, serve loop. |
| `auth_server.c` | Authoritative-server driver. |

## Building

```sh
make
```

Requires the `ldns` development package (`libldns-dev` or equivalent). Raw
socket injection requires elevated privileges (`CAP_NET_RAW`).

## Usage

On the attacker's authoritative host:

```sh
sudo ./auth_server
```

On the attacker's client host:

```sh
sudo ./poison_client
```

Neither program prints output; success is observed by querying the resolver for
the victim host afterward.

## Lab/target assumptions

- A recursive resolver (a deliberately old BIND 9.x) that uses a fixed or
  predictable UDP source port, enabling the transaction-ID race.
- The private lab topology hard-coded in `lab_config.h` (resolver, root,
  attacker authoritative, and attacker client on `192.168.1.0/24`).
- The attacker can inject spoofed UDP packets toward the resolver.

## License

MIT. See the [LICENSE](../LICENSE) at the repository root.
