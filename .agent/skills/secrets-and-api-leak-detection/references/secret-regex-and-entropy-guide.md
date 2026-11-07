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
| **OpenAI / LLM API Key** | `sk-[a-zA-Z0-9]{20,}` | Model quota consumption and sensitive prompt extraction. |
| **Database Connection Strings** | `(postgres\|mysql\|mongodb\|redis)://[^:]+:[^@]+@[^/]+` | Direct database cluster access and data exposure. |
| **JWT Tokens** | `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}` | Authentication state theft and session impersonation. |

## 2. Sensitive Document & Environment File Targets

* **Environment Configurations:** `.env`, `.env.local`, `.env.staging`, `.env.production`, `.env.backup`
* **Cloud & Server Manifests:** `credentials.json`, `service-account.json`, `id_rsa`, `id_ed25519`, `kubeconfig`
* **Internal Documents & Backups:** `*.dump`, `*.sql`, `backup.tar.gz`, `*.docx`, `*.pdf` containing internal system credentials

## 3. Shannon Entropy Formula
$$H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$
* Standard English prose entropy: $\approx 3.0 - 3.5$
* Base64/Hex cryptographic secret entropy: $\ge 4.5$

