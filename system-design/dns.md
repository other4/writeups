---
title: "Domain Name System (DNS) — How the Internet's Phone Book Works"
description: "A complete guide to DNS: how domain name resolution works, the types of DNS servers, record types, caching, and why DNS matters in distributed system design."
author: ["name": "Rajendra Pancholi", "email": "rpancholi522@gmail.com"]
created: "2026-04-18"
updated: "2026-04-18"
thumbnail: "/images/dns.png"
tags: [dns, networking, system-design, infrastructure, domain-name]
keywords: ["How DNS works", "DNS record types", "DNS caching explained", "Domain Name System system design", "DNS resolver vs authoritative nameserver"]
---

# Domain Name System (DNS) — How the Internet's Phone Book Works

Humans remember names. Computers communicate via IP addresses. The **Domain Name System (DNS)** is the hierarchical, decentralized naming infrastructure that bridges this gap — translating human-readable domain names like `google.com` into machine-readable IP addresses like `142.250.80.46`.

Without DNS, every user would need to memorize raw IP addresses to access any website. With DNS, the internet becomes navigable by name.

![Domain Name System](/images/dns.png)

---

## How DNS Resolution Works

DNS lookup is not a single step — it involves a chain of servers working together to resolve a domain name into an IP address.

![DNS Resolution Flow](/images/dns-resolution.png)

Here is the full 8-step DNS resolution process:

1. A user types `example.com` into a browser. The query leaves the client and reaches a **DNS Resolver** (typically provided by the ISP or configured as 8.8.8.8 for Google DNS).
2. The DNS Resolver queries a **DNS Root Nameserver**, which has no specific domain information but knows where to route the query next.
3. The Root Nameserver responds with the address of the appropriate **TLD (Top-Level Domain) Nameserver** based on the domain extension (`.com`, `.org`, `.io`, etc.).
4. The DNS Resolver queries the `.com` **TLD Nameserver**.
5. The TLD Nameserver responds with the address of the **Authoritative Nameserver** for `example.com`.
6. The DNS Resolver queries the **Authoritative Nameserver** for `example.com`.
7. The Authoritative Nameserver returns the **IP address** (A record) for `example.com`.
8. The DNS Resolver returns the IP address to the browser. The browser can now make an HTTP request to that IP.

This entire process typically completes in **20–120 milliseconds**, and subsequent lookups are dramatically faster due to caching.

---

## The Four Types of DNS Servers

### 1. DNS Resolver (Recursive Resolver)
The **first stop** in a DNS query. It acts as an intermediary between the client and the DNS namespace. Upon receiving a query, it either serves a cached response or begins the recursive resolution process by querying root, TLD, and authoritative nameservers.

Commonly operated by ISPs, or available as public resolvers (Google: `8.8.8.8`, Cloudflare: `1.1.1.1`).

### 2. DNS Root Nameserver
There are **13 root nameserver types** (labeled A through M), though each is replicated via Anycast routing across hundreds of physical locations worldwide. They don't know specific domain IP addresses — they direct resolvers to the appropriate TLD nameserver.

Operated by: [ICANN](https://www.icann.org) and partner organizations.

### 3. TLD Nameserver
Maintains information for all domains sharing a common extension. There are two categories:
- **Generic TLDs (gTLD):** `.com`, `.org`, `.net`, `.edu`, `.gov`
- **Country Code TLDs (ccTLD):** `.uk`, `.us`, `.in`, `.jp`, `.de`

Managed by: [IANA](https://www.iana.org) (a branch of ICANN).

### 4. Authoritative DNS Server
The **final authority** for a specific domain. It holds the actual DNS records for `example.com` and returns the definitive answer. If the domain doesn't exist, it returns an `NXDOMAIN` response.

---

## DNS Query Types

| Query Type | Description |
|---|---|
| **Recursive** | Client asks the resolver to return a complete answer or an error. The resolver does all the legwork. |
| **Iterative** | The resolver returns the best answer it has (possibly a referral to another nameserver). The client must follow up. |
| **Non-Recursive** | The resolver has the answer in cache and returns it immediately without contacting other servers. |

---

## DNS Record Types

DNS records (zone files) store specific information about a domain. Each record has a **TTL (Time to Live)** value that controls how long it can be cached.

| Record Type | Full Name | Purpose |
|---|---|---|
| **A** | Address | Maps domain → IPv4 address |
| **AAAA** | IPv6 Address | Maps domain → IPv6 address |
| **CNAME** | Canonical Name | Alias from one domain to another (no IP, just a redirect) |
| **MX** | Mail Exchanger | Directs email to mail servers |
| **TXT** | Text Record | Stores arbitrary text; used for SPF, DKIM, domain verification |
| **NS** | Name Server | Specifies authoritative nameservers for the domain |
| **SOA** | Start of Authority | Contains admin metadata (primary nameserver, admin email, serial number) |
| **SRV** | Service Location | Specifies hostname and port for specific services |
| **PTR** | Reverse Pointer | Maps IP address → domain (reverse DNS lookup) |
| **CERT** | Certificate | Stores public key certificates |

**Example DNS Records for `example.com`:**

```
example.com.     300    IN    A       93.184.216.34
example.com.     300    IN    AAAA    2606:2800:220:1:248:1893:25c8:1946
www.example.com. 300    IN    CNAME   example.com.
example.com.     3600   IN    MX      10 mail.example.com.
example.com.     3600   IN    TXT     "v=spf1 include:_spf.google.com ~all"
```

---

## DNS Caching

Caching is what makes DNS practical at internet scale. Without caching, every single web request would require 8+ round trips across the globe.

**Where DNS is cached:**

1. **Browser cache** — Modern browsers cache DNS for seconds to minutes.
2. **Operating system cache** — The OS maintains its own DNS resolver cache.
3. **Recursive resolver cache** — The ISP's resolver caches responses for the duration of the record's TTL.

**TTL (Time to Live):** Every DNS record specifies how long it can be cached (in seconds). When the TTL expires, the cache discards the record and a fresh lookup is performed.

**System Design Consideration:**
- **Short TTL (60–300s):** Use when you need rapid failover capability (e.g., during a database migration). Increases resolver load.
- **Long TTL (3600–86400s):** Use for stable endpoints to reduce DNS query load. Increases propagation delay when you change records.

---

## Subdomains

A subdomain is an additional part of the main domain, logically separating a website into distinct sections:

```
blog.example.com      → Company blog
api.example.com       → REST API endpoint
admin.example.com     → Internal admin panel
cdn.example.com       → Static assets
```

Each subdomain can have independent DNS records pointing to entirely different servers or services.

---

## DNS Load Balancing

DNS can perform rudimentary load balancing by returning multiple A records for a single domain (Round-Robin DNS). When a client queries `example.com`, the resolver returns multiple IP addresses in rotating order.

**Limitations of DNS load balancing:**
- DNS has no health check mechanism — it returns the same IPs even if servers are down.
- Client-side caching means clients may continue hitting a failed server until TTL expires.
- No support for session affinity (sticky sessions).

For production systems, proper load balancers (AWS ELB, NGINX, HAProxy) are used at the application layer, with DNS pointing to the load balancer endpoint.

---

## Reverse DNS

Reverse DNS does the opposite of forward DNS — it resolves an **IP address back to a domain name**, using PTR records. Commonly used by:

- **Email servers** — To validate that a sending server's IP actually corresponds to its claimed domain (anti-spam measure).
- **Security logging** — To identify the hostname associated with a suspicious IP address.
- **Network diagnostics** — Tools like `traceroute` and `nmap` use reverse DNS to display hostnames.

---

## Widely Used DNS Solutions

| Provider | Notes |
|---|---|
| [Amazon Route 53](https://aws.amazon.com/route53) | AWS-native, health checks, routing policies (geo, latency, failover) |
| [Cloudflare DNS](https://www.cloudflare.com/dns) | 1.1.1.1, privacy-focused, DDoS protection |
| [Google Cloud DNS](https://cloud.google.com/dns) | Anycast-based, 100% SLA |
| [Azure DNS](https://azure.microsoft.com/services/dns) | Integrated with Azure resource management |
| [NS1](https://ns1.com) | Traffic management and intelligent routing |

---

## System Design Takeaways

- DNS is a **critical single point of dependency** — DNS outages can take down entire services. Use multiple DNS providers or services with built-in redundancy.
- Use **short TTLs during deployments or failovers** to reduce the blast radius of misconfigurations.
- **DNS-based routing** (geo-routing, latency-based routing in Route 53) can be a simple, cost-effective way to direct users to the nearest regional deployment.
- **DNSSEC** adds cryptographic signatures to DNS records to prevent DNS spoofing and cache poisoning attacks.
- Always monitor your DNS records as part of your infrastructure observability stack.
