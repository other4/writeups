# 1. What is the HTTP Host Header?

* In **HTTP/1.1 requests**, the `Host` header specifies **which website (domain)** the client wants.
* Example:

  ```
  GET /home HTTP/1.1
  Host: example.com
  ```
* Why important?

  * Servers often host **multiple domains** on the same IP.
  * They rely on `Host` to route requests to the correct site.
* Problem: If servers/apps **trust this header too much**, attackers can exploit it.

---

## 2. What are Host Header Attacks?

When attackers **manipulate the Host header**, they can:

* Mislead the server or application.
* Cause **security flaws** like:

  * Password reset poisoning
  * Cache poisoning
  * Authentication bypass
  * Server-Side Request Forgery (SSRF)
  * Information disclosure (finding hidden domains via brute force)

---

## 3. Tools Needed (per PortSwigger)

* **Burp Suite (Proxy, Repeater, Intruder)** → Modify and resend requests.
* Why Burp? Unlike some proxies, Burp separates **target IP** from the `Host` header → lets you test arbitrary/malformed values safely.

---

## 4. Testing for Vulnerabilities

### Step 1: Supply an arbitrary Host header

* Replace domain with something random, e.g.,

  ```
  Host: attacker.com
  ```
* If the app still responds, it might be vulnerable.
* Some servers use a **default fallback** domain → lucky case for attackers.
* But often you’ll get an **Invalid Host header** error → move to advanced techniques.

---

## 5. Advanced Techniques (Finding Weaknesses)

### (a) Flawed validation

* Some apps only **partially check** the header.
* Examples:

  * Ignore port numbers → `Host: site.com:bad` could inject payload.
  * Match subdomains poorly → `Host: notsite.com` may bypass.
  * Exploit compromised subdomain → `Host: hacked.site.com`.

---

### (b) Ambiguous requests

* Different systems (frontend vs backend) may interpret headers differently.
* Tricks:

  1. **Duplicate Host headers**

     ```
     Host: site.com
     Host: attacker.com
     ```

     * Frontend might use first, backend last → attacker gains control.
  2. **Absolute URL in request line**

     ```
     GET https://attacker.com/ HTTP/1.1
     Host: site.com
     ```

     * Routing confusion between request line vs Host header.
  3. **Line wrapping** (leading space/indentation):

     ```
     GET / HTTP/1.1
         Host: attacker.com
     Host: site.com
     ```

     * Different parsers may treat “wrapped” headers differently.

---

### (c) Inject host override headers

* Some proxies inject headers like `X-Forwarded-Host`.
* If backend trusts these, attacker can use them:

  ```
  Host: site.com
  X-Forwarded-Host: attacker.com
  ```
* Other variants:

  * `X-Host`
  * `X-Forwarded-Server`
  * `X-HTTP-Host-Override`
  * `Forwarded`

---

## 6. Exploiting Host Header Vulnerabilities

### A. Password Reset Poisoning

* If app uses `Host` to build password reset links:

  * Attacker sends request with malicious host.
  * Victim receives reset link pointing to attacker’s domain.
  * Attacker steals reset tokens.

---

### B. Web Cache Poisoning

* Cache stores responses based on `Host`.
* If attacker injects malicious header → cached for others.
* Turns **reflected bugs** into **stored attacks**.

---

### C. Classic Server-Side Exploits

* Inject payloads via Host header (SQLi, XSS, etc.).
* Example:

  ```
  Host: ' OR 1=1--
  ```

---

### D. Authentication Bypass

* Some apps allow access only from “internal” hosts.
* Attacker modifies Host → tricks system into thinking request is internal.

---

### E. Virtual Host Brute-Forcing

* Servers may host **hidden subdomains**.
* Attacker guesses/brute-forces Host values to discover intranet domains.
* Example:

  ```
  intranet.company.com
  dev.company.com
  staging.company.com
  ```

---

### F. Routing-Based SSRF

* Load balancers/proxies use Host to route requests.
* If not validated, attacker can send:

  ```
  Host: 192.168.0.10
  ```

  → forwards request to internal systems.
* Powerful because proxies often have **internal network access**.

---

### G. Connection State Attacks

* Some servers **reuse connections**.
* Validate only the **first request** on a connection.
* Attacker sends harmless first request → then malicious one with changed Host.

---

### H. SSRF via Malformed Request Line

* Custom proxies mis-parse request lines.
* Example:

  ```
  GET @intranet/admin HTTP/1.1
  Host: site.com
  ```
* Backend interprets as request to intranet.

---

## 7. Mitigations (Defenses)

* **Strictly validate Host headers** against a whitelist.
* Don’t build absolute URLs from user-supplied Host.
* Don’t rely on Host for access control/authentication.
* Disable unnecessary headers (`X-Forwarded-Host`, etc.) unless required.
* Apply **defense-in-depth**: input validation + firewall rules + secure proxy configs.

---

## 8. Why Important?

* Host header attacks are **underrated but high-impact**.
* Can lead to **account takeover, internal access, or full compromise**.
* Often overlooked in traditional web testing.

---

✅ **Quick Summary**

* The **Host header** is critical for HTTP routing.
* Poor validation makes it a strong **attack vector**.
* With Burp Suite, you can:

  * Test Host header manipulation.
  * Discover vulnerabilities like reset poisoning, cache poisoning, SSRF, and bypasses.
* Defenders must **validate strictly** and avoid trusting Host blindly.

# Accessing restricted functionality
by using `Host: localhost`

# Use cidr in `Host` header

CIDR notation

IP address ranges are commonly expressed using CIDR notation, for example, 192.168.0.0/16.

IPv4 addresses consist of four 8-bit decimal values known as "octets", each separated by a dot. The value of each octet can range from 0 to 255, meaning that the lowest possible IPv4 address would be 0.0.0.0 and the highest 255.255.255.255.

In CIDR notation, the lowest IP address in the range is written explicitly, followed by another number that indicates how many bits from the start of the given address are fixed for the entire range. For example, 10.0.0.0/8 indicates that the first 8 bits are fixed (the first octet). In other words, this range includes all IP addresses from 10.0.0.0 to 10.255.255.255.

Got it — here’s a concise **future-reference** cheat-sheet you can copy into notes. I kept values as placeholders where you must substitute your lab-specific tokens/IDs.

# Burp Repeater — single-connection group exploit (cheat-sheet)

**Goal:** Use two requests sent sequentially over a single connection so the second (Host: 192.168.0.1) reaches the admin panel and allow form POST.

---

## Preconditions

* You're authenticated in the lab (have a valid `session` cookie).
* You have an initial GET `/` request in Repeater.
* Replace placeholders (YOUR-LAB-ID, YOUR-LAB-COOKIE, YOUR-SESSION-COOKIE, YOUR-CSRF-TOKEN) with actual values.

---

# Host validation bypass via connection state attack

1. **Start from** a `GET /` request in Repeater.

2. **Modify request #1**

   * Change path to `/admin`
   * Change `Host:` header to `192.168.0.1`
   * Send — you’ll be redirected to the homepage (this is expected).

3. **Duplicate the tab** (so you have two identical requests).

4. **Create a group**

   * Add both tabs to a new group.

5. **Select the first tab and restore it**

   * Change path back to `/`
   * Change `Host:` header back to `YOUR-LAB-ID.h1-web-security-academy.net`

6. **Configure group send mode**

   * Next to **Send**, choose **Send group in sequence (single connection)**.

7. **Set connection header**

   * For the first request in the group, set `Connection: keep-alive` (so the server keeps the TCP connection open).

8. **Send the sequence**

   * Send the grouped sequence.
   * Observe responses: the second request (with `Host: 192.168.0.1`) should now reach the admin panel.

9. **Inspect the admin panel response**

   * Find the delete-user form and note the important fields:

     * `action` attribute (likely `/admin/delete`)
     * name of username input (e.g. `username`)
     * CSRF token name/value (e.g. `csrf` / `YOUR-CSRF-TOKEN`)

10. **Construct the form POST (on the second tab in the group)**

    * Example request format (use your real cookies and token):

      ```
      POST /admin/delete HTTP/1.1
      Host: 192.168.0.1
      Cookie: _lab=YOUR-LAB-COOKIE; session=YOUR-SESSION-COOKIE
      Content-Type: application/x-www-form-urlencoded
      Content-Length: CORRECT

      csrf=YOUR-CSRF-TOKEN&username=carlos
      ```
    * Ensure `Content-Length` matches the body.

11. **Send the two requests in sequence (single connection)**

    * The first request establishes the correct virtual-host routing for the connection, the second request (same connection) is accepted as admin and performs the form action.

---

## Notes & troubleshooting

* **Placeholders:** Replace `YOUR-LAB-ID`, `YOUR-LAB-COOKIE`, `YOUR-SESSION-COOKIE`, and `YOUR-CSRF-TOKEN` with values from your session and responses.
* **Single connection is key:** Must use *Send group in sequence (single connection)* so both requests travel over the same TCP connection.
* **Connection header:** `Connection: keep-alive` helps ensure the server doesn't close the connection between requests.
* **If it fails:** confirm cookies and CSRF token are current, check that `Content-Length` is correct, and verify both requests were indeed sent over the same connection (check Repeater connection/sequence indicators).

---
