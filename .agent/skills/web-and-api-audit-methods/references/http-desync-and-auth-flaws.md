# HTTP Desync, AuthN/AuthZ & SSRF Parser Differential Reference

## 1. SSRF URL Parser Differential Vectors

When a web application validates a user-supplied URL before fetching it:
1. **Authority Confusion (`@` and `\`):**
   * `https://allowed.example.com@169.254.169.254/latest/meta-data/`
   * `https://169.254.169.254\@allowed.example.com` (WHATWG browsers/parsers normalize `\` to `/`, whereas some RFC 3986 parsers treat `\@` as part of userinfo).
2. **Alternative IP Encodings:**
   * Decimal integer (`2130706433` for `127.0.0.1`), Octal (`0177.0.0.1`), Hex (`0x7f.0.0.1`), IPv6 mapped IPv4 (`[::ffff:127.0.0.1]`).
3. **DNS Rebinding (TOCTOU):**
   * Validator resolves hostname -> receives public IP -> passes check -> HTTP client re-resolves hostname (TTL=0) -> receives `127.0.0.1` or `169.254.169.254`.
   * **Fix:** Resolve once, validate the resolved IP against all RFC 1918 / RFC 4193 / link-local / loopback ranges, and pin the socket connection to that exact IP.

## 2. CORS Misconfiguration Severity Table

| `Origin` Request Header | `Access-Control-Allow-Origin` Response | `Access-Control-Allow-Credentials` | Risk Assessment |
|---|---|---|---|
| `https://evil.example` | `https://evil.example` (Reflected) | `true` | **CRITICAL:** Arbitrary cross-origin authenticated read access. |
| `null` (Sandboxed `iframe`) | `null` | `true` | **HIGH:** Exploitable via `<iframe sandbox="allow-scripts">` to read authenticated responses. |
| `https://target.com.evil.example` | `https://target.com.evil.example` | `true` | **HIGH:** Unanchored prefix regex flaw (`^https://target\.com`). |
| Any | `*` | `false` or absent | **INFO/LOW:** Public resource sharing (browsers block `*` with credentials). |

