# SQL Injection & HTTP Response Splitting

*Boolean-based blind SQLi and web-cache poisoning via response splitting.*

## Overview

Two independent tools that attack a web application and its reverse proxy:

- `blind_sqli` — extracts data through a boolean-based blind SQL injection.
- `response_splitting` — poisons the proxy cache via HTTP response splitting.

## How it works

### Blind SQL injection

The application's order-status page is a boolean oracle: it reports an order as
"sent" when an injected SQL condition evaluates true. The base query is kept
valid with a known-good order id and an `AND (<condition>)` clause is appended.
Each byte of target data is recovered with a binary search over its ASCII value
using predicates of the form `ASCII(SUBSTR((<select>), i, 1)) > mid`, about
seven requests per character. The tool discovers the user table and the
id/password column names from `information_schema`, then extracts the password
for the configured account and writes it in `*password*` form to a file.

### HTTP response splitting

One TCP connection to the reverse proxy carries two pipelined HTTP/1.1 requests.
The first targets a reflecting endpoint with a percent-encoded parameter
containing CRLF sequences; reflected into a response header it terminates the
intended response early and appends a second, fully formed HTTP response. The
second request fetches the page to be poisoned, and the proxy associates the
injected response with it, caching the attacker's content under that page's
cache key until expiry (controlled via `Last-Modified`).

Source layout:

| File | Role |
| --- | --- |
| `config.h` | Target/proxy addresses and shared constants. |
| `net_io.{c,h}` | TCP connect and full-write helpers (shared). |
| `url_encode.{c,h}` | Conservative URL encoder for SQL conditions. |
| `http_oracle.{c,h}` | Boolean oracle over the order-status response. |
| `blind_sqli.c` | Binary-search extraction and schema discovery. |
| `percent_encode.{c,h}` | RFC 3986 encoder for the split payload. |
| `response_splitting.c` | Payload construction and the two-request send. |

## Building

```sh
make
```

Builds both `blind_sqli` and `response_splitting`.

## Usage

```sh
./blind_sqli            # writes <marker>.txt with the recovered password
./response_splitting    # poisons the proxy cache entry for the target page
```

## Lab/target assumptions

- The web application (`192.168.1.202:80`) exposes an order-status endpoint
  vulnerable to SQL injection against a MySQL-family backend with
  `information_schema`.
- The reverse proxy (`192.168.1.202:8080`, a deliberately old Apache) uses
  message-boundary parsing and a Host+URL cache key, making it susceptible to
  response splitting.
- Addresses and endpoint names are hard-coded for the sandboxed lab.

## License

MIT. See the [LICENSE](../LICENSE) at the repository root.
