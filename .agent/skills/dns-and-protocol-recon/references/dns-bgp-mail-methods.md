# DNS, NSEC3, Mail Authentication & BGP/RPKI Deep Reference

## 1. RFC 5155 NSEC3 Wire-Format & Base32hex Cheat Sheet

* **Canonical Wire Format (`wire(fqdn)`):**
  Each label is lowercased and prefixed by its 1-byte length, terminated by `\x00`.
  * `com.` -> `\x03com\x00`
  * `pornhub.com.` -> `\x07pornhub\x03com\x00`
  * `*.com.` -> `\x01*\x03com\x00`
* **Iterative SHA-1 Definition (RFC 5155 §5):**
  * $k = 0$: $\text{IH}(\text{salt}, x, 0) = \text{SHA-1}(\text{wire}(x) \parallel \text{salt})$
  * $k > 0$: $\text{IH}(\text{salt}, x, k) = \text{SHA-1}(\text{IH}(\text{salt}, x, k-1) \parallel \text{salt})$
* **Base32hex Alphabet (RFC 4648 §7):**
  Standard Base32 (`A-Z2-7`) is mapped to `0123456789ABCDEFGHIJKLMNOPQRSTUV` so that lexicographical string comparison of Base32hex hashes matches binary byte-order comparison of raw SHA-1 digests.

## 2. Multi-Signer DNSSEC (RFC 8901) in Dual-Provider Architectures

When a domain delegates authority to two independent DNS providers simultaneously (e.g., AWS Route53 + UltraDNS) without `AXFR` zone transfers:
* Signing only one provider breaks resolution for every validating resolver that queries the unsigned provider.
* Signing both providers independently without importing each provider's Zone Signing Key (ZSK) into the other provider's `DNSKEY` RRset causes `SERVFAIL` when a resolver fetches the `DNSKEY` RRset from Provider A and an `RRSIG` from Provider B.
* **RFC 8901 Multi-Signer Model:** Cross-import ZSKs into both providers' apex `DNSKEY` RRsets and publish both providers' KSK `DS` records in the parent TLD zone.

