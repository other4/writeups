Great — I made **both**: (A) a compact, printable **1‑page bug‑hunting checklist** and (B) a prioritized, actionable **list of 50 concrete high‑level tests** for web apps (ethical, no exploit payloads). Use the checklist during testing; use the 50 tests as a menu to pick from based on scope and risk.

# A — One‑page bug‑hunting checklist (printable)

* Scope & rules

  * Confirm target(s) in-scope (domains, subdomains, APIs, mobile endpoints).
  * Confirm prohibited actions (data exfiltration, DoS, social engineering).
  * Get and save program contact & triage rules.

* Recon & mapping (quick)

  * Enumerate subdomains, endpoints, public repos, third‑party services.
  * Capture tech stack (server headers, JS libs, frameworks).
  * Catalog auth flows, roles, admin panels, API base paths.

* Prioritize targets

  * Highest value: auth flows, payment/billing, file upload, admin interfaces, APIs.
  * Next: user profile, data export, search, bulk operations.

* Testing basics (safe‑first)

  * Use intercepting proxy; start passive.
  * Take screenshots and save request/response traces.
  * Use low‑noise automated scans then manual verification.

* Test categories to cover (high level)

  * Authentication, sessions, MFA, password reset.
  * Authorization (horizontal/vertical), direct object refs.
  * Input validation (XSS, SQLi, injection), file handling.
  * Business logic (workflow, rate limits), APIs (undocumented endpoints).
  * Configs: CORS, exposed S3/backups, admin panels.
  * Dependencies: outdated libraries, public repos.

* Evidence & reporting

  * Repro steps (minimal): request → change → response → impact.
  * Impact statement: what an attacker achieves and who’s affected.
  * PoC: minimal, non‑destructive (screenshots, benign requests).
  * Suggested remediation and severity rationale.
  * Mark resolved and re‑test; include regression checks.

* Post‑report hygiene

  * Respect disclosure policy and embargoes.
  * Sanitize logs/screenshots (no real user data).
  * Follow up politely if no response after program SLA.

---

# B — Prioritized list: 50 concrete, high‑level tests (ethical, no exploit payloads)

> Ordering is prioritized for likely impact: start near top and move down as time allows.

1. **Login brute‑force policy** — Attempt many logins within allowed scope; observe lockouts, CAPTCHA, rate limiting. (Why: account takeover risk)
2. **Password reset flow** — Check if reset tokens are guessable, reusable, or overly long expiry. (Why: reset abuse → account takeover)
3. **MFA bypass checks** — Test backup codes, SMS/backup flows, OAuth flows, device linking. (Why: bypass MFA weakens protection)
4. **Session fixation / session reuse** — Check session IDs on login, logout, and across browsers. (Why: session hijack risk)
5. **Horizontal access control** — Access another user’s resources by changing user IDs. (Why: IDOR risk)
6. **Vertical privilege escalation** — Try admin endpoints with normal user token or role. (Why: broken auth)
7. **Direct Object Reference (IDOR) enumeration** — Increment/alter identifiers in URLs or json. (Why: sensitive data exposure)
8. **Unprotected admin/debug pages** — Probe common admin paths and debug endpoints. (Why: exposed management interfaces)
9. **CORS misconfiguration** — Check whether pages accept cross‑origin requests from arbitrary origins. (Why: data exfil via browsers)
10. **Exposed sensitive files / backups** — Check for .git, .env, backups, s3 buckets, or old logs. (Why: secrets/info leak)
11. **Open redirects** — Test redirect parameters to see if arbitrary URLs are allowed. (Why: phishing & token theft)
12. **CSRF (state changing requests)** — Verify anti‑CSRF tokens on POST/PUT/DELETE operations. (Why: unauthorized state changes)
13. **API rate‑limiting & abuse** — Test bulk endpoints (import/export, price updates) for throttling. (Why: business logic abuse or DoS)
14. **Pagination / data exposure** — Force large page numbers or page size changes to see undisclosed records. (Why: data leakage)
15. **File upload handling** — Test file type checks, content sniffing, storage location (public vs private). (Why: remote code, info leak)
16. **Reflected XSS (input → immediate output)** — Check form fields that reflect user input without context encoding. (Why: DOM or stored XSS risk)
17. **Stored XSS (persistent)** — Identify inputs saved server‑side and later rendered by other users. (Why: higher impact XSS)
18. **DOM XSS / client‑side sinks** — Inspect JS for unsafe innerHTML/use of user input. (Why: client exploitation vectors)
19. **SQL/NoSQL injection indicators** — Observe error messages, unusual responses to single quotes or boolean alterations. (Why: data manipulation risk)
20. **Command/OS injection indicators** — Check endpoints that pass data to system commands (look for error text). (Why: server compromise)
21. **Template injection / server‑side rendering** — Check templated fields for unusual render behavior. (Why: remote code possibility)
22. **JSON / XML parsing issues** — Send unexpected JSON structures, duplicate keys, or large nested objects. (Why: parser quirks → logic bypass)
23. **Header manipulation** — Modify Host, X‑Forwarded‑For, Referer, Origin to test routing, auth, or logging behavior. (Why: access or logging bypass)
24. **Cookie flags & secure attributes** — Check HttpOnly, Secure, SameSite on session cookies. (Why: cookie theft, CSRF risk)
25. **JWT/token issues** — Inspect token claims, expiry, alg typemismatch, or reuse tokens across users. (Why: token forgery/abuse)
26. **OAuth & SSO flows** — Test redirect URIs, token exchange, and client registration controls. (Why: SSO misconfig → account takeover)
27. **Client‑side logic trust** — Remove client JS checks and reattempt actions (price changes, role flags). (Why: tampering with client validation)
28. **Business logic abuse: price/quantity** — Try order flows, coupon stacking, refund logic, race conditions. (Why: monetary loss)
29. **Concurrency / race conditions** — Attempt near‑simultaneous requests for the same resource (e.g., withdraw funds twice). (Why: duplication / integrity issues)
30. **Undocumented / hidden API endpoints** — Browse JS, mobile clients, or public repos for API paths. (Why: hidden functionality)
31. **File download access control** — Access stored files with different user contexts; check direct URLs. (Why: leakage of private files)
32. **Upload file type override** — Upload a benign file with double extension or changed mime to test server checks. (Why: bypass naive checks)
33. **Content Security Policy (CSP) testing** — Check whether CSP is present and effective for scripts/styles. (Why: reduce XSS impact)
34. **Error message leakage** — Trigger errors and inspect stacktraces, DB errors, or path disclosures. (Why: gives attack info)
35. **Third‑party integration abuse** — Check webhooks, callbacks, or delegated services (CDN, analytics) for token or endpoint leaks. (Why: chain attacks)
36. **Dependency/version disclosure checks** — Identify library versions from headers/JS and compare to known CVEs (record responsibly). (Why: supply chain risk)
37. **Search / index manipulation** — Use search endpoints to retrieve data beyond UI filters (fuzzy queries, facets). (Why: data exposure)
38. **Content tampering & caching** — Test cached pages for user‑specific content being cached publicly. (Why: data leak via cache)
39. **Host header poisoning / virtual host checks** — Send unexpected Host header to test routing, links, and password reset links. (Why: phishing, token manipulation)
40. **Rate limit bypass methods** — Test IP rotation, param variation, or cookie changes to bypass throttles. (Why: abuse automation)
41. **Business process authorization** — Attempt actions meant for managers via API replay or role swapping. (Why: workflow abuse)
42. **Email / notification flows** — Test what information appears in notification bodies; check for sensitive info. (Why: info leakage via email)
43. **Mobile app backend checks** — Intercept mobile app API requests for extra params, tokens, or endpoints. (Why: mobile often exposes private APIs)
44. **Infrastructure / DNS checks** — Enumerate subdomains, MX, SPF/TXT records, and check for unused hosts. (Why: reduce attack surface; find staging)
45. **Logging & audit trails** — Trigger actions and verify what is logged; look for sensitive data in logs. (Why: compliance & info leak)
46. **Client certificate & TLS config** — Inspect certificate validity, TLS versions, and weak ciphers (non‑intrusive checks). (Why: transport security)
47. **Content type & serialization mismatches** — Submit unexpected content-type (text/xml to JSON endpoints). (Why: parsing bypass)
48. **Re‑test after disclosed fixes / patch validation** — When a public fix exists, test the same logic across endpoints and inputs. (Why: incomplete patches)
49. **Chaining low‑impact issues** — Combine info leak + IDOR or weak auth + CSRF to see aggregated impact. (Why: higher effective impact)
50. **Safe proof & remediation guidance** — For any confirmed issue, produce minimal reproducible PoC (non‑destructive), clear remediation steps, and tests to confirm fix. (Why: good reports get fixed faster)

---

If you want, I can:

* Convert the one‑page checklist into a downloadable PDF you can print, or
* Expand any item from the 50 into a short how‑to checklist (step‑by‑step safe tests and what evidence to collect), or
* Produce a compact “top 10 tests” quick card to keep on your desk.

Which of those three would you like next?
