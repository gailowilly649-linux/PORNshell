---
name: web-and-api-audit-methods
description: >-
  Use this skill when auditing web applications, REST/GraphQL/gRPC APIs, HTTP
  security headers, CORS policies, JWT/OAuth2 authentication flows, request
  smuggling/desync boundaries, SSRF parser differentials, or BOLA/IDOR access
  controls.
---

# Web, API, AuthN/AuthZ & HTTP Protocol Audit Methods

This skill provides systematic tactics for auditing modern web architectures, reverse-proxy chains, API authorization graphs, and token-based authentication.

## Core Web & API Audit Methodologies

### 1. Reverse-Proxy & HTTP Parser Desynchronization
* **HTTP/1.1 `Content-Length` vs `Transfer-Encoding` (`CL.TE` / `TE.CL` / `TE.TE`):** Check whether the front-end CDN/load-balancer and back-end origin server disagree on framing when obfuscated `Transfer-Encoding` headers are present.
* **HTTP/2 to HTTP/1.1 Downgrade (`H2.CL` / `H2.TE`):** Verify whether the edge proxy strips `Transfer-Encoding` and validates `:authority` / content length when translating HTTP/2 frames into HTTP/1.1 backend connections.
* **Hop-by-Hop Header Abuse & Trust Spoofing:** Check whether the backend trusts `X-Forwarded-For`, `X-Real-IP`, `X-Original-URL`, or `X-Rewrite-URL` when sent directly by an external client.

### 2. API Object-Graph & Authorization Matrix Auditing (BOLA / BFLA / Mass Assignment)
* **BOLA / IDOR:** Test whether UUIDs, sequential IDs, or composite keys in path/query/JSON/GraphQL variables enforce tenant and user ownership checks at the data-access layer.
* **GraphQL Batching, Aliasing & Introspection:** Check for deeply nested circular fragments, alias-based rate-limit bypasses, and field-level authorization mismatches on edges/connections.

### 3. JWT, OAuth2 & Session Cryptography Checks
* **JWT Header & Algorithm Confusion:**
  * `alg: none` acceptance.
  * RS256-to-HS256 key confusion (signing with the public RSA key as an HMAC secret).
  * Unvalidated `jku`, `x5u`, or `kid` header injection (path traversal or SQLi in `kid` lookup).
* **OAuth2 / OIDC Flow Flaws:** Missing `state` CSRF binding, permissive `redirect_uri` regex/subdomain matching, or token leakage via `Referer` headers.

### 4. CORS, CSP & Transport Header Posture
* Check whether `Access-Control-Allow-Origin` dynamically reflects arbitrary `Origin` headers alongside `Access-Control-Allow-Credentials: true`.
* Audit `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (unsafe-inline, wildcard sources, JSONP endpoints), `X-Frame-Options`, and `X-Content-Type-Options`.

---

## Automated Execution Steps

1. **Run the Automated 10%–100% HTTP Header & CORS Posture Inspector:**
   Execute [http_header_posture.py](./scripts/http_header_posture.py) to evaluate captured or live HTTP response headers across 10 automated stages:
   ```bash
   python3 .agent/skills/web-and-api-audit-methods/scripts/http_header_posture.py
   ```
2. **Consult the HTTP Desync, Auth & SSRF Reference:**
   Read [http-desync-and-auth-flaws.md](./references/http-desync-and-auth-flaws.md) for detailed checklists.

