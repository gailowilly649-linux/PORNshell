---
name: dns-and-protocol-recon
description: >-
  Use this skill when auditing DNS infrastructure, multi-provider authoritative
  nameserver parity, SOA split-brain, SPF AST lookup limits, DKIM ASN.1 RSA key
  sizes, DMARC/MTA-STS/CAA posture, RFC 5155 NSEC3 cryptographic hashes, or
  BGP/RPKI OriginAS routing posture.
---

# Authoritative DNS, Mail Posture, NSEC3 & BGP/RPKI Audit Tactics

This skill codifies protocol-level techniques for uncovering misconfigurations, split-brain DNS zones, SPF lookup-exhaustion vectors, weak DKIM keys, NSEC3 Opt-Out proofs, and BGP prefix hijack exposure.

## Core Protocol Audit Methods

### 1. Multi-NS Authoritative Parity & SOA Split-Brain
* Bypass recursive resolver caches (`dig +norec @<ns>` or raw UDP/TCP DNS queries with `RD=0`) against every authoritative nameserver across all providers (e.g., AWS Route53 vs. UltraDNS).
* Compare:
  * **SOA Serial & RNAME:** Independent serials (e.g., `1` vs `2014036770`) prove dual active control planes rather than primary-secondary `AXFR`/`IXFR` replication.
  * **SOA Minimum / NCACHE TTL Asymmetry (RFC 2308):** Different negative-caching TTLs cause `NXDOMAIN` responses to persist for different durations depending on which authoritative server a recursive resolver hits.
  * **Zone Transfer (`AXFR`) Posture:** Verify whether TCP port 53 `AXFR` requests are reset (`TCP RST`) or refused (`REFUSED` / `FormError`).

### 2. Recursive SPF AST & 10-Lookup Budget Auditing (RFC 7208)
* **255-Byte Wire Split Inspection:** Check multi-string `TXT` records for tokens split across string boundaries (e.g., `"ip4:67.231.15" "1.26"`).
* **Duplicate & Cross-Mechanism Redundancy:** Normalize all `ip4:`/`ip6:` CIDRs and compare resolved `a:`/`mx:` mechanisms against explicit `ip4:` literals to eliminate wasted DNS lookups.
* **Subdomain & Parked Domain Posture:** Check whether non-mail subdomains publish `v=spf1 -all` and null `MX` (`0 .`).

### 3. Cryptographic DKIM & DMARC Alignment Inspection
* Decode the Base64 `p=` ASN.1 `SubjectPublicKeyInfo` structure from `_domainkey` TXT records to extract the exact RSA modulus size (`1024-bit` vs `2048-bit`) and flag obsoleted `g=*` tags.
* Inspect `_dmarc.<domain>` for `p=none` monitoring-only policies, missing `sp=` subdomain policies, and external `rua=`/`ruf=` destinations requiring RFC 7489 `_report._dmarc` authorization records.

### 4. Automated RFC 5155 NSEC3 Hash & Interval Verification
* Compute canonical wire-format iterative SHA-1 + Base32hex (`0-9A-V`) hashes:
  $$\text{IH}(\text{salt}, x, 0) = \text{Base32hex}(\text{SHA-1}(\text{wire}(x) \parallel \text{salt}))$$
* Verify Closest Encloser exact matches and Next Closer open-interval coverage `(owner_hash < H(target) < next_owner_hash)` alongside the `Flags=1` Opt-Out bit (RFC 5155 §7.2.7).

### 5. BGP OriginAS & RPKI ROA Validation
* When querying `whois.arin.net` for a CIDR block that matches multiple net-handles, always prefix the query with `+` (`n + <CIDR>`) so ARIN returns full records including `OriginAS`.
* Cross-check the Origin ASN and prefix against RPKI ROAs to detect invalid or `NOT_FOUND` prefixes vulnerable to sub-prefix BGP hijacking.

---

## Automated Execution Steps

1. **Run the Zero-Flag 10%–100% Automated DNS & NSEC3 Pipeline:**
   Execute [dns_posture_audit.py](../../../dns_posture_audit.py) from the workspace root:
   ```bash
   ./dns_posture_audit.py
   ```
2. **Compute Arbitrary NSEC3 Hashes On-Demand:**
   ```bash
   python3 dns_posture_audit.py --hash-name example.com. --salt - --iterations 0
   ```
3. **Consult Deep Protocol Reference:**
   Read [dns-bgp-mail-methods.md](./references/dns-bgp-mail-methods.md) for wire-format details and remediation templates.

