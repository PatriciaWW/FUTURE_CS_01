# Findings: demo.testfire.net (Altoro Mutual)

## 1. Scope and method
| Item | Detail |
|---|---|
| Target | demo.testfire.net (65.61.137.117), a public, intentionally vulnerable training site |
| Testing type | Reconnaissance and configuration review. No exploitation, no authenticated testing. |
| Tools | Nmap 7.991, curl, OWASP ZAP (alerts), online security-headers scanner, Firefox developer tools |
| Dates | 2026-10-12 to 2026-10-13 |
| Source of detail | `observations.md` (observation IDs O1–O29 are cited below) |

**Severity key (suggested, align with your scheme or CVSS):** High = directly exploitable with major impact; Medium = weakens a core protection or enables an attack under common conditions; Low = hardening gap or information disclosure; Informational = no direct risk.

## 2. Summary of findings
| ID | Finding | Severity | Affected | Standards mapping* | Confirmed by |
|---|---|---|---|---|---|
| F1 | Expired TLS certificate | Medium | 443 | A02:2021; CWE-324 | Nmap, curl |
| F2 | Deprecated TLS 1.0/1.1 enabled | Medium | 443 | A02:2021; CWE-326 | Nmap (2 runs) |
| F3 | Weak 1024-bit Diffie-Hellman parameters | Medium | 443 | A02:2021; CWE-326 | Nmap (2 runs) |
| F4 | Plaintext HTTP with no HTTPS redirect | Medium | 80 (8080 untested) | A02:2021; CWE-319 | curl, header scan |
| F5 | Session cookie lacks `Secure` flag | Medium | 80, 8080 | A05:2021; CWE-614 | Nmap, curl |
| F6 | Session cookie lacks `SameSite` | Low | 80, 443, 8080 | A05:2021; CWE-1275 | Nmap, curl, ZAP |
| F7 | Missing Content-Security-Policy | Medium | Web app | A05:2021; CWE-693 | ZAP, header scan, curl |
| F8 | Missing anti-clickjacking protection | Medium | Web app | A05:2021; CWE-1021 | ZAP, header scan, curl |
| F9 | Missing `X-Content-Type-Options` | Low | Web app | A05:2021; CWE-693 | ZAP, header scan, curl |
| F10 | Missing Referrer-Policy and Permissions-Policy | Low | Web app | A05:2021 | Header scan, curl |
| F11 | Server/technology version disclosure | Low | 80, 443, 8080 | A05:2021; CWE-200 | Nmap, curl, ZAP |
| F12 | Informational items | Informational | Various | n/a | Nmap, browser |

\*Mappings are suggested. Verify the OWASP Top 10 (2021) and CWE references against the official lists before submitting.

### Severity distribution
| Severity | Count | IDs |
|---|---|---|
| High | 0 | none |
| Medium | 7 | F1, F2, F3, F4, F5, F7, F8 |
| Low | 4 | F6, F9, F10, F11 |
| Informational | 1 | F12 |

## 3. Detailed findings

### F1: Expired TLS certificate
- **Severity:** Medium
- **Affected:** https://demo.testfire.net (443/tcp)
- **Description:** The certificate for `demo.testfire.net` (Sectigo DV, RSA 2048, SHA-256) was valid from 2025-05-21 to **2026-06-21**. At the time of testing (2026-10-13) it had been expired for about 114 days.
- **Evidence:** Nmap `ssl-cert` output (`Not valid after: 2026-06-21T23:59:59`, repeated on two scan days); `curl -I https://demo.testfire.net` returned `curl: (60) SSL certificate OpenSSL verify result: certificate has expired (10)`. (O11)
- **Impact:** Browsers show a security warning and clients that validate certificates refuse the connection. Users learn to click through warnings, which makes man-in-the-middle attacks harder to notice. Automated clients and APIs fail outright.
- **Recommendation:** Issue and install a new certificate, and automate renewal (for example ACME/Let's Encrypt or the CA's renewal tooling) with expiry monitoring and alerts.

### F2: Deprecated TLS 1.0 and TLS 1.1 enabled
- **Severity:** Medium
- **Affected:** 443/tcp
- **Description:** The server accepts TLS 1.0 and 1.1, which were deprecated by RFC 8996. TLS 1.3 was not listed.
- **Evidence:** `nmap --script ssl-enum-ciphers` lists TLSv1.0, TLSv1.1 and TLSv1.2 (two runs, identical). (O13, O18a)
- **Impact:** Fails common compliance baselines (for example PCI DSS) and keeps legacy, CBC-only suites available, which are historically linked to BEAST and Lucky13-type attacks. This is a risk class and was not exploited.
- **Recommendation:** Disable TLS 1.0 and 1.1, keep TLS 1.2 and enable TLS 1.3.

### F3: Weak 1024-bit Diffie-Hellman parameters
- **Severity:** Medium
- **Affected:** 443/tcp, all DHE cipher suites
- **Description:** DHE suites use 1024-bit DH parameters. Nmap warns that the key exchange is weaker than the 2048-bit certificate key.
- **Evidence:** `Key exchange (dh 1024) of lower strength than certificate key` under TLS 1.0, 1.1 and 1.2. (O14)
- **Impact:** This is the weak-DH class of issue associated with Logjam (CVE-2015-4000). Susceptibility was not tested directly.
- **Recommendation:** Use DH parameters of 2048 bits or more, or remove DHE suites and rely on ECDHE.

### F4: Plaintext HTTP served with no redirect to HTTPS
- **Severity:** Medium
- **Affected:** 80/tcp (confirmed); 8080/tcp (open, not re-tested with curl)
- **Description:** The application is served over cleartext HTTP. The response to `http://demo.testfire.net` is `200 OK` with no redirect, and no `Strict-Transport-Security` header was seen.
- **Evidence:** `curl -sI http://demo.testfire.net` output; security-headers scan warning "Site is using HTTP ... did not redirect to HTTPS". (O6, O26)
- **Impact:** Traffic, including session cookies and any submitted credentials, can be read or altered by an attacker on the network path. Combined with F1, users have no reliably secure way to reach the site.
- **Recommendation:** Redirect all HTTP to HTTPS (301), add HSTS once the certificate is valid, and close port 8080 if it is not needed.

### F5: Session cookie missing the `Secure` flag
- **Severity:** Medium
- **Affected:** `JSESSIONID` on 80/tcp and 8080/tcp
- **Description:** The session cookie is issued over HTTP without `Secure`. It does carry `HttpOnly`. On 443 the cookie does have `Secure`.
- **Evidence:** Nmap `http-headers` output; `curl -sI http://demo.testfire.net | grep -i set-cookie` → `JSESSIONID=...; Path=/; HttpOnly`. (O8, O27)
- **Impact:** The cookie can be sent in cleartext and intercepted, enabling session hijacking when a session is authenticated over HTTP.
- **Recommendation:** Set `Secure`, `HttpOnly` and `SameSite` on all session cookies, and serve the app over HTTPS only.

### F6: Session cookie missing the `SameSite` attribute
- **Severity:** Low
- **Affected:** `JSESSIONID` on all ports
- **Description:** No `SameSite` attribute is set.
- **Evidence:** Nmap, curl and ZAP alert "Cookie without SameSite Attribute". (O8, O22, O27)
- **Impact:** Weaker built-in protection against cross-site request forgery and cross-site leakage of the cookie.
- **Recommendation:** Set `SameSite=Lax` (or `Strict` where the application allows) and add anti-CSRF tokens.

### F7: Missing Content-Security-Policy
- **Severity:** Medium (rated Medium by ZAP)
- **Affected:** Web application responses
- **Description:** No `Content-Security-Policy` header is returned.
- **Evidence:** ZAP alert "Content Security Policy (CSP) Header Not Set"; header-scan "Missing Headers" list; curl response headers. (O19, O25)
- **Impact:** Removes a key browser-side mitigation against cross-site scripting and content injection.
- **Recommendation:** Deploy a CSP that restricts script and content sources, starting in report-only mode and then enforcing.

### F8: Missing anti-clickjacking protection
- **Severity:** Medium (rated Medium by ZAP)
- **Affected:** Web application responses
- **Description:** Neither `X-Frame-Options` nor CSP `frame-ancestors` is set.
- **Evidence:** ZAP alert "Missing Anti-clickjacking Header"; header-scan list. (O20, O25)
- **Impact:** Pages can be embedded in another site's frame, allowing clickjacking (tricking users into clicking hidden controls).
- **Recommendation:** Send `X-Frame-Options: SAMEORIGIN` or `Content-Security-Policy: frame-ancestors 'self'`.

### F9: Missing `X-Content-Type-Options`
- **Severity:** Low
- **Affected:** Web application responses (2 instances in ZAP)
- **Description:** The `nosniff` header is not sent.
- **Evidence:** ZAP alert "X-Content-Type-Options Header Missing (2)"; header-scan list. (O21, O25)
- **Impact:** Browsers may MIME-sniff responses, which can turn some uploaded or reflected content into executable script.
- **Recommendation:** Add `X-Content-Type-Options: nosniff` to all responses.

### F10: Missing Referrer-Policy and Permissions-Policy
- **Severity:** Low
- **Affected:** Web application responses
- **Description:** Neither header is set.
- **Evidence:** Header-scan "Missing Headers" list; absent from curl response. (O25)
- **Impact:** Browsers apply default referrer behaviour, which may leak URLs to other sites, and browser features are not explicitly restricted.
- **Recommendation:** Set `Referrer-Policy: strict-origin-when-cross-origin` (or stricter) and a restrictive `Permissions-Policy`.

### F11: Server and technology version disclosure
- **Severity:** Low
- **Affected:** 80, 443, 8080
- **Description:** Responses include `Server: Apache-Coyote/1.1`, and service detection identifies Apache Tomcat/Coyote JSP engine 1.1.
- **Evidence:** Nmap service scan and `http-server-header`; curl headers; ZAP alert "Server Leaks Version Information ... (2)". (O4, O5, O23)
- **Impact:** Helps an attacker choose exploits targeted at the identified technology.
- **Recommendation:** Remove or genericise the `Server` header and keep Tomcat patched.

### F12: Informational items
- **Severity:** Informational
- TLS 1.3 not listed, and the server uses client cipher preference (`cipher preference: client`). (O16)
- Nmap's "least strength: A" summary is misleading because it ignores F1–F3. Do not present it as a clean result. (O18)
- Firefox reports "Almost Standards Mode" (legacy or missing DOCTYPE) and shows an error row for `/favicon.ico`. (O28, O28a)
- ZAP "Session Management Response Identified" confirms `JSESSIONID` is the session token. (O24)
- `ISO-8859-1` charset in use. (O10)

## 4. Positive observations
- Only 3 of the top 100 TCP ports are open; the rest are filtered. (O1)
- RSA 2048-bit key and SHA-256 signature on the certificate. (O12)
- No NULL, export, RC4 or 3DES cipher suites; ECDHE and AES-GCM are available. (O17)
- `HttpOnly` is set on the session cookie, and `Secure` is set on the HTTPS response. (O7)

## 5. Recommended remediation priority
| Priority | Action | Fixes |
|---|---|---|
| 1 | Install a valid certificate and automate renewal | F1 |
| 2 | Redirect HTTP to HTTPS, add HSTS, close 8080 if unused | F4 |
| 3 | Disable TLS 1.0/1.1, enable TLS 1.3, fix DH size | F2, F3 |
| 4 | Harden session cookies (`Secure`, `HttpOnly`, `SameSite`) | F5, F6 |
| 5 | Add CSP, anti-framing and `nosniff` headers | F7, F8, F9 |
| 6 | Add Referrer-Policy and Permissions-Policy; hide server banner | F10, F11 |

## 6. Evidence index
| Evidence | Supports |
|---|---|
| evidence/nmap/01_service_scan.txt | F11 |
| evidence/nmap/02_http_info.txt | F5, F6, F11 |
| evidence/nmap/03_tls.txt (and 2026-10-12 TLS screenshots) | F1, F2, F3, F12 |
| evidence/headers/http_headers.txt | F4, F7, F8, F9, F10 |
| evidence/headers/cookies.txt | F5, F6 |
| curl certificate-expired screenshot | F1 |
| ZAP alerts screenshot | F6, F7, F8, F9, F11, F12 |
| Security-headers scan screenshot | F4, F7, F8, F9, F10 |
| Firefox console screenshot | F12 |
| evidence/headers/js_libraries.txt | Not used (no visible output) |

## 7. Gaps to close before submitting
- Capture HTTPS headers with `curl -sIk https://demo.testfire.net` to confirm HSTS and the cookie flags on 443.
- Check port 8080 with curl to confirm F4 and F5 there.
- Capture ZAP alert details (affected URLs, instance counts) for the screenshots.
- Re-run or paste the JavaScript library check, or leave it out of the report.
- Decide whether your scope includes application-layer testing (authentication, input validation). None has been done, so the report should say so.
