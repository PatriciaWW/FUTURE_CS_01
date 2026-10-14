# Vulnerability Assessment: demo.testfire.net

A reconnaissance and configuration review of **demo.testfire.net (Altoro Mutual)**, carried out as a training exercise. This repository holds the observations, findings, evidence and report from the assessment.

> **Disclaimer:** The target is a public, intentionally vulnerable demo application intended for security testing practice. All testing was limited to non-intrusive scanning and passive analysis. Do not run these techniques against systems you do not own or have explicit written permission to test.

---

## 1. Website tested

| Item | Detail |
|---|---|
| Name | Altoro Mutual (demo banking application) |
| Host | demo.testfire.net |
| IP address | 65.61.137.117 |
| Technology observed | Apache Tomcat / Coyote JSP engine 1.1 |
| Testing dates | 12–13 October 2026 |

## 2. Scope

**In scope**
- Host `demo.testfire.net` (65.61.137.117)
- Top 100 TCP ports, with detailed checks on the open ports **80, 443 and 8080**
- TLS certificate, protocol and cipher configuration (port 443)
- HTTP response headers and session cookie attributes
- Passive analysis of the web application as seen without logging in

**Out of scope**
- Exploitation of any vulnerability
- Authenticated testing
- Input-validation testing (for example SQL injection and XSS)
- UDP scanning and full port-range scanning
- Denial-of-service or any other disruptive testing

## 3. Tools used

| Tool | Version | Purpose |
|---|---|---|
| Nmap | 7.991 | Port and service discovery; HTTP header scripts (`http-headers`, `http-title`, `http-server-header`); TLS analysis (`ssl-cert`, `ssl-enum-ciphers`) |
| curl | n/a | Checking HTTP response headers, cookie attributes and the HTTPS certificate error |
| OWASP ZAP | n/a | Passive web-application alerts (missing security headers, cookie and server-banner issues) |
| Online security-headers scanner | n/a | Cross-checking missing HTTP security headers and the HTTP-to-HTTPS redirect |
| Firefox developer tools | n/a | Browser console warnings |

### Commands used
```bash
nmap -sV -Pn --top-ports 100 demo.testfire.net -oN evidence/nmap/01_service_scan.txt
nmap -Pn -p 80,443,8080 --script http-headers,http-title,http-server-header demo.testfire.net -oN evidence/nmap/02_http_info.txt
nmap -Pn -p 443 --script ssl-cert,ssl-enum-ciphers demo.testfire.net -oN evidence/nmap/03_tls.txt
curl -sI http://demo.testfire.net | tee evidence/headers/http_headers.txt
curl -sI http://demo.testfire.net | grep -i "set-cookie" | tee evidence/headers/cookies.txt
curl -I --max-time 20 https://demo.testfire.net
```

## 4. Repository contents

| Path | Description |
|---|---|
| `observations.md` | Raw observations (O1–O29) from each tool, with a cross-tool comparison |
| `findings.md` | Twelve findings (F1–F12) with severity, evidence, impact and recommendations |
| `evidence/nmap/` | Nmap scan output |
| `evidence/headers/` | curl header and cookie output |
| Report (PDF) | Final report, if included in this repository |

## 5. Summary of results

Twelve findings: **7 Medium, 4 Low, 1 Informational** and no High findings within this scope. The main issues are an expired TLS certificate, plaintext HTTP with no redirect to HTTPS, a session cookie without the `Secure` flag, deprecated TLS 1.0/1.1, and missing browser security headers. See `findings.md` for details.

## 6. Limitations

- Severity ratings are suggested and not CVSS-scored.
- HTTP checks used HEAD requests only, and HTTPS (443) and port 8080 headers were not fully captured with curl.
- No application-layer testing was performed, so such vulnerabilities are not covered.
