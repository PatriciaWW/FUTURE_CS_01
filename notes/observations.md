# Observations: demo.testfire.net

> Target is Altoro Mutual, a public, intentionally vulnerable training site. Findings below are configuration and exposure observations from scanning and passive analysis only. See `findings.md` for the formal findings write-up.

## 1. Scan metadata
| Item | Value |
|---|---|
| Target | demo.testfire.net (65.61.137.117) |
| Tools | Nmap 7.991, curl, OWASP ZAP (alerts), online security-headers scanner, Firefox developer tools |
| Nmap service and HTTP scans | 2026-10-13, 02:19–02:21 EDT (~06:21 GMT) |
| Nmap TLS scan | Run twice: 2026-10-12 15:31 EDT and 2026-10-13 02:21 EDT. Results identical. |
| curl checks | 2026-10-13, ~06:27 GMT |
| Host status | Up (~0.24–0.26 s latency) |
| Evidence files | evidence/nmap/01_service_scan.txt, 02_http_info.txt, 03_tls.txt; evidence/headers/http_headers.txt, cookies.txt, js_libraries.txt; ZAP, header-scan and browser console screenshots |

## 2. Attack surface (01_service_scan)
| Port | State | Service | Version banner |
|---|---|---|---|
| 80/tcp | open | http | Apache Tomcat/Coyote JSP engine 1.1 |
| 443/tcp | open | ssl/http | Apache Tomcat/Coyote JSP engine 1.1 |
| 8080/tcp | open | http (labelled http-proxy) | Apache Tomcat/Coyote JSP engine 1.1 |

- **O1:** Only 3 of the top 100 TCP ports are open. The other 97 are *filtered (no response)*, so a firewall is silently dropping packets. This indicates a small attack surface.
- **O2:** All three ports serve the same application (page title "Altoro Mutual"), reachable over plaintext HTTP (80, 8080) and HTTPS (443).
- **O3:** Nmap's "http-proxy" label for 8080 is based on the port number. There is no evidence it is an actual proxy.
- **O4:** The technology stack (Apache Tomcat / Coyote / JSP) is disclosed on every port. This helps an attacker target known Tomcat weaknesses. Nmap did not report an exact version.

## 3. HTTP response observations (02_http_info, curl)
- **O5:** The `Server: Apache-Coyote/1.1` header is exposed on all ports (information disclosure). Confirmed by Nmap, curl and ZAP (see O23).
- **O6:** Plaintext HTTP on 80 and 8080 is reachable alongside HTTPS. **Confirmed for port 80:** `curl -sI http://demo.testfire.net` returned `HTTP/1.1 200 OK` directly, with no `301/302` redirect and no `Location` header. The security-headers scan also warned "Site is using HTTP" and "did not redirect to HTTPS" (O26). Port 8080 was not re-tested with curl.
- **O7:** A `JSESSIONID` cookie is issued to unauthenticated visitors on every port.

| Port | HttpOnly | Secure | SameSite |
|---|---|---|---|
| 80 | Yes | **No** | Not set |
| 443 | Yes | Yes | Not set |
| 8080 | Yes | **No** | Not set |

- **O8:** The session cookie on 80 and 8080 lacks the `Secure` flag, so it can be sent over cleartext HTTP and intercepted. No `SameSite` attribute is set on any port.
- **O9:** The HEAD responses show no `Strict-Transport-Security`, `X-Frame-Options`, `Content-Security-Policy` or `X-Content-Type-Options` headers. **Confirmed on port 80 by curl:** the full response contained only `Server`, `Set-Cookie`, `Content-Type`, `Transfer-Encoding` and `Date`. No `Cache-Control` was sent either. HTTPS response headers are still untested (see section 9).
- **O9a:** curl and Nmap agree on O5, O7 and O8, which gives two independent tools for each.
- **O10:** The response charset is ISO-8859-1 (legacy encoding, minor).

## 4. TLS observations (03_tls, port 443)

### Certificate
| Attribute | Value |
|---|---|
| Subject / SAN | demo.testfire.net |
| Issuer | Sectigo RSA Domain Validation Secure Server CA |
| Key / signature | RSA 2048-bit / SHA-256 with RSA |
| Valid from – to | 2025-05-21 to **2026-06-21** |

- **O11:** **The certificate expired on 2026-06-21, about 114 days before the scan date.** Nmap printed the dates but did not flag the expiry. **Independently confirmed by curl:** `curl -I https://demo.testfire.net` failed with `curl: (60) SSL certificate OpenSSL verify result: certificate has expired (10)`. Clients that validate certificates by default refuse the connection, and users are pushed to click through warnings.
- **O12:** The key size (2048-bit RSA) and signature algorithm (SHA-256) are acceptable.

### Protocols and ciphers
| Protocol | Offered | Assessment |
|---|---|---|
| TLS 1.0 | Yes | Deprecated (RFC 8996) |
| TLS 1.1 | Yes | Deprecated (RFC 8996) |
| TLS 1.2 | Yes | Acceptable |
| TLS 1.3 | Not listed | Not offered, or not detected by this scan |

- **O13:** Deprecated TLS 1.0 and 1.1 are still enabled. This fails modern compliance baselines such as PCI DSS.
- **O14:** All DHE cipher suites use **1024-bit Diffie-Hellman parameters**, and Nmap warns they are weaker than the 2048-bit certificate key (the warning appears under TLS 1.0, 1.1 and 1.2). This is the weak-DH class of issue behind Logjam (CVE-2015-4000).
- **O15:** TLS 1.0/1.1 offer only CBC-mode suites, historically associated with BEAST and Lucky13-type attacks. Treat as a risk class, not a confirmed exploit.
- **O16:** The server does not enforce cipher order (`cipher preference: client`).
- **O17:** Positives: no NULL, export, RC4 or 3DES suites. ECDHE (forward secrecy) and AES-GCM are available on TLS 1.2.
- **O18:** Nmap's "A" grades are per cipher suite and the summary reads "least strength: A". This is misleading, because it ignores the deprecated protocols, 1024-bit DH and the expired certificate. Do not present it as a clean result.
- **O18a:** The TLS scan was repeated on a second day with identical certificate dates, protocols and ciphers, so the results are reproducible.

## 5. Web application observations (ZAP, header scan, browser)

### OWASP ZAP alerts (6 alerts)
| Alert | ZAP risk (flag colour) | Instances |
|---|---|---|
| Content Security Policy (CSP) Header Not Set | Medium (orange) | not shown |
| Missing Anti-clickjacking Header | Medium (orange) | not shown |
| Cookie without SameSite Attribute | Low (yellow) | not shown |
| Server Leaks Version Information via "Server" HTTP Response Header Field | Low (yellow) | 2 |
| X-Content-Type-Options Header Missing | Low (yellow) | 2 |
| Session Management Response Identified | Informational (blue) | not shown |

- **O19:** No `Content-Security-Policy` header is set, so the browser has no allow-list to limit script and content sources. This removes a key mitigation against XSS.
- **O20:** No anti-clickjacking header (`X-Frame-Options` or CSP `frame-ancestors`) is set, so the pages can be framed by other sites and are open to clickjacking.
- **O21:** `X-Content-Type-Options: nosniff` is missing (2 instances), so browsers may MIME-sniff responses.
- **O22:** The session cookie has no `SameSite` attribute. ZAP agrees with Nmap and curl (O8).
- **O23:** The `Server` header leaks version information (2 instances), matching O5.
- **O24:** "Session Management Response Identified" is informational. It confirms ZAP recognised `JSESSIONID` as the session token, which is useful for later session testing.

### Security-headers scan
- **O25:** The scan lists five missing headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, **Referrer-Policy** and **Permissions-Policy**. The last two were not flagged by ZAP.
- **O26:** The scan warns that the site was served over HTTP and did not redirect to HTTPS, matching O6.

### Cookie check (curl)
- **O27:** `curl -sI http://demo.testfire.net | grep -i set-cookie` returned `Set-Cookie: JSESSIONID=...; Path=/; HttpOnly`. This shows `HttpOnly` is set, and `Secure` and `SameSite` are absent on the plaintext HTTP response. The session ID value differs between requests, which is expected for new unauthenticated sessions. Whether the ID is regenerated after login (session fixation) has not been tested.

### Browser console (Firefox)
- **O28:** The console reports "This page is in Almost Standards Mode" (missing or legacy `<!DOCTYPE>`), which indicates old markup. It is a low-value observation with no direct security impact.
- **O28a:** The request `GET http://demo.testfire.net/favicon.ico` is shown as an error row. The status code is not visible in the screenshot. Informational only.

### JavaScript libraries
- **O29:** A curl and grep command was run to look for jQuery, Bootstrap, Angular and React references, saved to `evidence/headers/js_libraries.txt`. **No output is visible in the screenshot, so this check is inconclusive.** Do not report outdated libraries unless the file shows matches.

## 6. Cross-tool corroboration
| Observation | Nmap | curl | ZAP | Header scan |
|---|---|---|---|---|
| Server banner disclosed | ✔ | ✔ | ✔ | |
| Cookie lacks SameSite | ✔ | ✔ | ✔ | |
| Cookie lacks Secure (HTTP) | ✔ | ✔ | | |
| No HTTPS redirect | | ✔ | | ✔ |
| CSP missing | ✔ | ✔ | ✔ | ✔ |
| Anti-clickjacking missing | ✔ | ✔ | ✔ | ✔ |
| X-Content-Type-Options missing | ✔ | ✔ | ✔ | ✔ |
| Referrer/Permissions-Policy missing | ✔ | ✔ | | ✔ |
| Certificate expired | ✔ (dates) | ✔ (error 60) | | |
| TLS 1.0/1.1 and 1024-bit DH | ✔ (2 runs) | | | |

Findings backed by two or more tools are the strongest to present in the report.

## 7. Findings summary
Full detail is in `findings.md`.

| ID | Finding | Evidence | Suggested severity |
|---|---|---|---|
| F1 | Expired TLS certificate | 03_tls, curl error 60 | Medium |
| F2 | TLS 1.0/1.1 enabled | 03_tls (2 runs) | Medium |
| F3 | Weak 1024-bit DH parameters | 03_tls (2 runs) | Medium |
| F4 | Plaintext HTTP with no HTTPS redirect | curl, header scan, 01, 02 | Medium |
| F5 | Session cookie lacks Secure flag | 02_http_info, cookies.txt | Medium |
| F6 | Session cookie lacks SameSite | Nmap, curl, ZAP | Low |
| F7 | Missing Content-Security-Policy | ZAP, header scan, curl | Medium |
| F8 | Missing anti-clickjacking protection | ZAP, header scan, curl | Medium |
| F9 | Missing X-Content-Type-Options | ZAP, header scan, curl | Low |
| F10 | Missing Referrer-Policy and Permissions-Policy | Header scan | Low |
| F11 | Server/technology banner disclosure | Nmap, curl, ZAP | Low |
| F12 | Informational: no TLS 1.3, client cipher preference, legacy DOCTYPE | 03_tls, console | Informational |

## 8. Limitations
- Only the top 100 TCP ports were scanned; UDP and the full port range were not.
- HTTP checks used HEAD requests only (Nmap and `curl -I`).
- The curl header check covered port 80 only. HTTPS (443) and 8080 headers have not been captured with curl.
- ZAP results are alert names only in the screenshot; affected URLs and instance counts were not captured for four of the six alerts.
- The JavaScript library check has no visible output.
- No exploitation, input-validation, or authenticated testing was done. Findings are configuration and exposure observations.
- Severities are suggested ratings; align them with your report's scheme (e.g. CVSS).

## 9. Follow-up checks

| Check | Status | Result |
|---|---|---|
| `curl -sI http://demo.testfire.net` | Done | 200 OK, no HTTPS redirect, no security headers |
| `curl -I https://demo.testfire.net` | Done | Failed: certificate has expired |
| Cookie check (`grep -i set-cookie`) | Done | HttpOnly only |
| ZAP alerts, header scan, browser console | Done | See section 5 |
| JS library check | **Output missing** | Re-run or paste the contents of `js_libraries.txt` |
| `curl -sIk https://demo.testfire.net` | **To do** | Captures HTTPS headers (HSTS, `Secure` cookie) |
| `curl -sI http://demo.testfire.net:8080` | **To do** | Confirms port 8080 behaves like port 80 |
| ZAP alert details (URLs, instances) | **To do** | Click each alert and screenshot the affected URLs |

```
curl -sIk https://demo.testfire.net | tee evidence/headers/https_headers.txt
curl -sI http://demo.testfire.net:8080 | tee evidence/headers/http8080_headers.txt
curl -I https://demo.testfire.net 2>&1 | tee evidence/headers/https_cert_error.txt
```
