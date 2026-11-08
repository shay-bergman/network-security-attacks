# Network Security Attacks

*Implementations of classic network and web attack techniques in C.*

> **Authorized use only.** Every tool here was written and tested in a private,
> controlled security lab against deliberately vulnerable, sandboxed targets —
> old BIND/Apache builds and hosts on a private `192.168.x.x` network, with all
> addresses and endpoints hard-coded for that environment. This collection is
> for learning and defensive understanding. Do not run these tools against any
> system you do not own or have explicit written permission to test. Running
> them outside such a setting is likely illegal.

## Overview

This repository collects from-scratch C implementations of four well-known
offensive techniques, each reduced to its essential mechanics so the underlying
weakness is clear. The point is understanding — how each attack is constructed
at the byte and protocol level, and therefore what defenses address it.

A neutral placeholder is used wherever the original lab required a unique
identifier as a proof-of-exploitation marker; it has no functional role.

## Modules

| Module | Technique |
| --- | --- |
| [`buffer-overflow/`](buffer-overflow/) | Stack buffer overflow with position-independent shellcode. |
| [`dns-cache-poisoning/`](dns-cache-poisoning/) | Kaminsky-style DNS cache poisoning against a recursive resolver. |
| [`xss/`](xss/) | Reflected, stored, and DOM-based XSS cookie exfiltration. |
| [`sql-injection-and-response-splitting/`](sql-injection-and-response-splitting/) | Boolean-based blind SQL injection and HTTP response splitting. |

Each module has its own README with the technique write-up, file layout, build
steps, and target assumptions.

## Building

Each module is self-contained with its own `Makefile`:

```sh
cd <module> && make
```

Requirements: a C11 compiler (`gcc` or `clang`) and a POSIX environment. The
DNS module additionally needs the `ldns` development library and raw-socket
privileges.

## Defensive takeaways

- **Buffer overflow** — bounds-checked input handling, stack canaries,
  non-executable stacks, and ASLR.
- **DNS cache poisoning** — source-port and transaction-ID randomization,
  DNSSEC, and 0x20 query-name encoding.
- **XSS** — context-aware output encoding, a Content Security Policy, and
  `HttpOnly` session cookies.
- **SQL injection / response splitting** — parameterized queries and strict
  rejection of control characters (CR/LF) in reflected values.

## License

MIT — Copyright (c) 2026 Shay Bergman. See [LICENSE](LICENSE).
