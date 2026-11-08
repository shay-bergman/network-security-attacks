# Cross-Site Scripting (XSS)

*Reflected, stored, and DOM-based XSS cookie exfiltration.*

## Overview

An attacker-controlled HTTP server collects session cookies stolen by injected
JavaScript and replays them against the target web application to retrieve
protected resources. The same collection server backs all three XSS variants;
a separate injector seeds the stored-XSS payload.

## How it works

Injected JavaScript runs in the victim's browser and sends `document.cookie` to
the collection server as the `cookieId1234` query parameter. The server
extracts the cookie, opens its own connection to the target application
presenting that cookie, and saves the full response to a file.

- **Reflected** — a URL-encoded `<script>` payload is placed in a vulnerable
  query parameter that the application echoes into its HTML unescaped, so the
  script runs on load (see `payloads/reflected.txt`).
- **Stored** — `inject_stored` POSTs a `<script>` payload that the application
  persists; when an administrator later views it, the payload runs in their
  browser.
- **DOM-based** — the payload is carried in the URL fragment and processed
  entirely client-side. Because the page writes user data via `innerHTML`, an
  `<img onerror=...>` element is used instead of a `<script>` tag to trigger
  execution reliably (see `payloads/dom.txt`).

Source layout:

| File | Role |
| --- | --- |
| `config.h` | Target, attacker, and cookie-parameter configuration. |
| `sockio.{c,h}` | Socket timeout and full-write helpers. |
| `cookie.{c,h}` | Cookie extraction from an inbound request. |
| `exfil.{c,h}` | Cookie replay and protected-resource retrieval. |
| `cookie_logger.c` | Collection server (serves all three variants). |
| `inject_stored.c` | Standalone stored-XSS payload injector. |
| `payloads/` | Ready-to-use reflected and DOM-based payload URLs. |

## Building

```sh
make
```

## Usage

Run the collection server, giving it the protected page to fetch and the output
file for the retrieved response:

```sh
./cookie_logger /account.php spoofed-reflected.txt
```

Then trigger the chosen variant:

- Reflected / DOM-based: open the URL in `payloads/reflected.txt` or
  `payloads/dom.txt` in the victim browser.
- Stored: seed the payload once, then wait for an administrator to view it:

  ```sh
  ./inject_stored
  ```

## Lab/target assumptions

- The target web application (`192.168.1.203:80`) is vulnerable to the relevant
  injection and performs no output encoding or input sanitization.
- The attacker collection server is reachable by the victim browser at
  `192.168.1.201:5555`.
- Session cookies are not marked `HttpOnly` (so client-side script can read
  them), consistent with the sandboxed lab configuration.

## License

MIT. See the [LICENSE](../LICENSE) at the repository root.
