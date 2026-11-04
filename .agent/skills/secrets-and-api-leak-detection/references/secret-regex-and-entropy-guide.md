# Secret Token Patterns & Entropy Reference

## 1. High-Confidence Secret Signatures

| Service | Token Pattern / Prefix | Typical Risk |
|---|---|---|
| **AWS Access Key ID** | `(A3T[A-Z0-9]\|AKIA\|AGPA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA\|ASIA)[A-Z0-9]{16}` | Perimeter access to AWS API. |
| **AWS Secret Access Key** | `(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]` | Full API authentication when paired with Key ID. |
| **GitHub Token** | `gh[pousr]_[A-Za-z0-9_]{36,255}` | Repository write, package deployment, organization admin. |
| **Google API Key** | `AIza[0-9A-Za-z\\-_]{35}` | Google Maps / GCP quota consumption and service access. |
| **Slack API Token** | `xox[baprs]-[0-9a-zA-Z]{10,48}` | Slack bot and message interception. |
| **Private Keys** | `-----BEGIN (RSA\|DSA\|EC\|OPENSSH\|PGP) PRIVATE KEY-----` | Direct SSH access or TLS certificate compromise. |

## 2. Shannon Entropy Formula
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
* Standard English prose entropy: $\approx 3.0 - 3.5$
* Base64/Hex cryptographic secret entropy: $\ge 4.5$

