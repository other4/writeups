## Find explicit VDP / responsible-disclosure pages on Indian domains

* `site:*.in "vulnerability disclosure policy"`
* `site:gov.in "vulnerability disclosure"`
* `site:*.in "responsible disclosure"`
* `site:*.in intitle:"vulnerability disclosure"`
* `site:*.in "vulnerability disclosure policy" OR "responsible disclosure" OR "security disclosure"`

## Find bug-bounty / HackerOne / Bugcrowd / PSIRT pages for Indian orgs

* `site:*.in "bug bounty" OR "bugbounty"`
* `site:*.in inurl:hackerone OR inurl:bugcrowd`
* `site:*.in "product security" "vulnerability" "policy"`

## Search for security.txt files (fast way to discover contact/VDP)

* `site:*.in "/.well-known/security.txt"`
* `inurl:".well-known/security.txt" site:*.in`
* `inurl:"/security.txt" site:*.in`

(`security.txt` is the standard format for pubishing security contacts — see RFC 9116). ([IETF Datatracker][2])

## Locate PDF or policy documents mentioning disclosure (useful for gov/org policies)

* `site:gov.in filetype:pdf "vulnerability disclosure"`
* `site:*.in filetype:pdf "vulnerability disclosure policy"`

## Narrow to sectors (finance, telecom, education)

* `site:*.in "vulnerability disclosure" (bank OR finance OR "payment")`
* `site:*.in "responsible disclosure" (telecom OR "mobile")`
* `site:edu.in "vulnerability" OR "responsible disclosure"`

## Find security contacts indexed by third-party projects

* `"findsecuritycontacts" site:findsecuritycontacts.com india`
  (or visit findsecuritycontacts.com to query domains directly — it indexes `security.txt` entries). ([Find Security Contacts][3])

## Brute-force patterns for org security pages

* `site:*.in inurl:security inurl:contact`
* `site:*.in intitle:"security" "contact" "report"`

---

# How to interpret results & next steps

* If you find a `security.txt` file, it usually contains `Contact:` and `Policy:` fields telling you how to report issues and whether testing is allowed. RFC 9116 explains the format. ([IETF Datatracker][2])
* If you find a VDP page, read it carefully: it will say scope (what you may test), out-of-bounds items, and how they prefer reports and encryption keys. ([securitytxt.org][4])
* CERT-IN (the national CERT) is a useful hub for coordination if you can’t find a vendor contact or if the issue impacts multiple Indian entities. ([CERT-In][1])

---
