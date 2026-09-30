# Aegis-Web Threat Model

This document outlines the security architecture, threat analysis, implemented defensive controls, and residual risks for the Aegis-Web testing platform.

---

## 1. Threat Matrix & Defensive Controls

| Threat Category | Specific Threat Scenario | Implemented Platform Control | Residual Risk & Operational Guidance |
| :--- | :--- | :--- | :--- |
| **SSRF (Server-Side Request Forgery)** | Attacker configures target pointing to internal networks (`10.0.0.0/8`, `192.168.0.0/16`, `127.0.0.1`, `169.254.169.254`, `::1`). | Strict multi-layer SSRF filter (`net_guard.py`): validates schemes (`http`/`https` only), prohibits userinfo (`user:pass@`), resolves all IPs, and blocks link-local, cloud metadata, loopback, multicast, and RFC1918 ranges. | In authorized internal environments, Lab Mode allows private subnets. Cloud metadata subnets (`169.254.0.0/16`, `100.100.100.200`) remain permanently blocked regardless of mode. |
| **DNS Rebinding** | Target domain resolves to a public IP during registration or pre-flight check, then rebinds to an internal/metadata IP on subsequent requests. | `safe_get` performs DNS resolution once and pins the HTTP connection to the resolved IP address directly, passing original hostname in the `Host` header and SNI. | Standard replayer requests currently resolve per run; deploy within dedicated egress network namespaces in untrusted cloud deployments. |
| **Hostile Target: Response Flood** | Target returns infinite streams or gigabyte-sized payloads to exhaust worker memory. | Response body streaming hard caps: 200 KB during browser crawler recording, 2 MB during HTTP differential replay, and 64 KB during ownership verification `safe_get`. | Memory spikes bounded to predictable buffer allocations per active scan. |
| **Hostile Target: Slowloris / Tar Pit** | Target delays sending bytes indefinitely to tie up scanner workers. | Strict HTTP client timeouts (`connect=5.0s, read=15.0s`) and hard global scan deadline enforced via `SCAN_TIMEOUT_SECONDS` (worker marks job as `failed`). | Worker thread is guaranteed to terminate when timeout threshold is exceeded. |
| **Hostile Target: Internal Redirects** | Target returns HTTP 302 redirecting the scanner to an internal cloud metadata service. | `safe_get` disables automatic HTTP client redirects, manually inspects the `Location` header, and re-validates the destination URL through `validate_url` before following (max 3 redirects). | Playwright page navigation in crawler is constrained to target domain scope. |
| **Hostile Target: Malicious Downloads** | Target triggers executable or archive downloads during browser crawl. | Playwright browser context explicitly ignores and suppresses downloads (`accept_downloads=False`). | Browser never downloads or writes untrusted binaries to local disk. |
| **Hostile Target: Stored XSS in UI** | Malicious target serves HTML/JavaScript payloads in headers, URLs, or bodies designed to execute when analysts inspect findings. | Frontend renders **all** target-derived strings (headers, diffs, titles, URLs) as native React text nodes inside `<pre>`. `dangerouslySetInnerHTML` is prohibited across the entire codebase. | Zero script execution in dashboard; confirmed by Vitest XSS suite (`DiffViewer.test.tsx`). |
| **Credential Exposure at Rest** | Target account passwords stored in plain text in database compromises victim apps on DB breach. | Passwords encrypted at rest using AES-128-CBC + HMAC-SHA256 (`cryptography.fernet.Fernet`). Key is loaded exclusively from environment variable. | If backend host is compromised with runtime environment variables, encryption key is accessible. |
| **Credential Leakage in Logs & APIs** | Credentials returned in API payloads, stored in audit events, or dumped in stack traces. | (1) Database passwords decrypted strictly in-memory during active scans.<br/>(2) `TargetAccountResponse` schema completely omits password field.<br/>(3) `redact_headers` and `redact_body` redact sensitive keys.<br/>(4) Worker replaces plain passwords with `[REDACTED]`. | In-memory values visible in core dumps or memory debuggers if root access obtained on host. |
| **Cross-Tenant Data Tampering** | User B attempts to view or modify User A's targets, accounts, scans, or findings. | All database queries strictly enforce `owner_id == current_user.id`. Requests for other users' resources return **404 Not Found** (never 403) to prevent resource existence disclosure. | Comprehensive tenant isolation verified in `test_isolation.py`. |
| **JWT Forgery & Algorithm Confusion** | Attacker creates forged tokens using `alg: none` or switches asymmetric keys to symmetric keys. | PyJWT decoder explicitly requires `algorithms=["HS256"]` and verifies signatures with secret. Minimum secret length is 32 characters; server halts on weak secret. | Tokens stored in `sessionStorage` are tab-scoped; compromised extension on same origin could read session storage. |
| **Authentication Brute Force** | Automated dictionary attacks against platform `/auth/login` endpoint. | In-memory sliding-window rate limiter restricts failed login attempts to 5 attempts per minute per `(IP, email)` tuple. Passwords hashed with Argon2id. | Distributed brute force from large IP pool could attempt distributed dictionary attacks. |
| **Platform Abuse for Denial of Service** | Malicious user registers third-party websites to launch denial-of-service replay floods. | Target domain ownership verification is mandatory before scans can be submitted. Requires placing a high-entropy hex token in `/.well-known/aegis-verification.txt`. | Lab Mode allows unverified targets for local private tests; Lab Mode is admin-restricted and can be globally disabled via `ENABLE_LAB_MODE=false`. |
| **Destructive Requests on Target** | Replayer modifies state or triggers irreversible deletions on target systems. | Stage 1 replayer is strictly restricted to HTTP `GET` methods. The crawler skips links containing `logout`, `signout`, `delete`, `remove`, `destroy`. | State-changing GET requests (anti-pattern) could potentially trigger mutations if target violates HTTP idempotent specifications. |
| **Dependency Vulnerabilities** | Outdated or vulnerable third-party Python/Node packages introduce remote execution. | CI pipeline includes automated AST vulnerability scanning (`bandit`), Python package auditing (`pip-audit`), and frontend dependency auditing (`npm audit`). | Zero-day vulnerabilities in upstream browser engines (Chromium) or Python core. |

---

## 2. Authentication & Token Storage Trade-off

Aegis-Web stores authentication tokens in React state mirrored to `sessionStorage` (tab-scoped storage) rather than `localStorage` or `httpOnly` cookies:
- **Pros:**
  - Prevents cross-tab session leakage and token persistence after browser tabs are closed.
  - Avoids CSRF vulnerabilities associated with ambient credential cookies.
  - Eliminates complex SameSite / Cross-Origin Resource Sharing cookie friction during local development.
- **Trade-off:**
  - Tokens in `sessionStorage` can be accessed by scripts running in the same origin if Cross-Site Scripting (XSS) is present.
  - This risk is mitigated on the platform frontend by strictly disallowing `dangerouslySetInnerHTML`, escaping all output, and maintaining strict Content Security Policy headers (`nosniff`, `no-referrer`, `no-store`).

---

## 3. Stage 2 Probing & Secret Handling Rules

Stage 2 introduces active JavaScript bundle inspection (`modules/js_analysis.py`) and security misconfiguration checks (`modules/misconfig.py`):
- **Read-Only Probe Constraint:** All Stage 2 probes (CORS origin checks, sensitive file checks, open redirect parameter probes, source map fetches) are strictly passive or read-only HTTP `GET` requests. They never submit state-changing data, never invoke DELETE/PUT/POST operations, and never follow external redirect targets.
- **Zero Secret Re-use:** Any credential or secret discovered during client script analysis (such as AWS keys, Google API keys, or private key blocks) is **never used by the scanner engine** to attempt unauthorized access or escalation against third-party or target APIs.
- **Strict Masking:** All discovered secrets are masked immediately upon extraction (retaining only the first 4 and last 2 characters, e.g. `AKIA...LE`). Raw unmasked credentials are never logged, never stored in the database, and never returned in API payloads or finding evidence.
- **Safe Baseline Diffing:** Exposed file probes use dynamic, randomized 404 baselines to prevent alert fatigue from Single Page Application catch-all routes.
