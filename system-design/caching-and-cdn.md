---
title: "Caching and CDN — Speeding Up Systems at Every Layer"
description: "A complete guide to caching strategies, eviction policies, cache invalidation, distributed caches, and Content Delivery Networks (CDN) for building fast, scalable systems."
author: ["name": "Rajendra Pancholi", "email": "rpancholi522@gmail.com"]
created: "2026-04-18"
updated: "2026-04-18"
thumbnail: "/images/caching-cdn.png"
tags: [caching, cdn, system-design, performance, scalability, redis, memcached]
keywords: ["Caching strategies system design", "Cache eviction policies", "CDN explained", "Write-through vs write-back cache", "Redis vs Memcached", "Content Delivery Network"]
---

# Caching and CDN — Speeding Up Systems at Every Layer

> *"There are only two hard things in Computer Science: cache invalidation and naming things."* — Phil Karlton

Caching is the practice of **storing frequently accessed data in a fast-access storage layer** so that future requests for that data are served faster. It is one of the most powerful and universally applicable performance optimization techniques in system design.

A Content Delivery Network (CDN) is caching taken global — storing static content at geographically distributed edge locations so that users around the world experience low latency.

![Caching Architecture](/images/caching-cdn.png)

---

## Why Caching Matters

Every time a request hits a backend server and queries a database, it incurs:
- **Network latency** (round trips between services)
- **Database query time** (disk I/O, query parsing, locking)
- **Compute cost** (CPU cycles for computation)

Caching eliminates these costs for repeated access patterns by serving precomputed or previously fetched results from memory — orders of magnitude faster than disk-based storage.

**Caches exploit the principle of locality of reference:** data that was recently requested is likely to be requested again soon.

---

## Cache Hit and Cache Miss

| Term | Description |
|---|---|
| **Cache Hit** | Requested data is found in the cache — served immediately without going to the primary store |
| **Cache Miss** | Requested data is not in the cache — must be fetched from the primary store and added to cache |
| **Cold Cache** | Cache is empty or barely populated — most requests are misses (startup state) |
| **Warm Cache** | Cache has been populated with commonly accessed data — mix of hits and misses |
| **Hot Cache** | Highly populated cache with most requests served as hits — optimal steady-state |

---

## Cache Invalidation Strategies

Cache invalidation — ensuring cached data doesn't become stale — is the hardest part of caching. There are three primary strategies:

### Write-Through Cache

Data is written to **both the cache and the database simultaneously**. On every write operation, the cache is updated in real time.

![Write-Through Cache](/images/write-through-cache.png)

**Advantages:**
- Cache is always consistent with the database
- No risk of serving stale data after a write

**Disadvantages:**
- Higher write latency (must wait for both cache and DB write to complete)
- Every write hits the cache even for data that may never be read again (wasted cache space)

**Best for:** Systems where data consistency is critical and write frequency is manageable (e.g., user profile updates).

### Write-Around Cache

Writes go **directly to the database, bypassing the cache**. The cache is only populated when data is read (on cache miss).

![Write-Around Cache](/images/write-around-cache.png)

**Advantages:**
- Cache is not polluted with data that may never be read
- Reduces cache churn for write-heavy workloads

**Disadvantages:**
- Read after write will cause a cache miss (latency spike)
- Not suitable for applications with high read-after-write patterns

**Best for:** Write-heavy workloads where reads are infrequent or on different data than what was just written.

### Write-Back (Write-Behind) Cache

Data is written **only to the cache**. The write is acknowledged immediately. The cache then asynchronously syncs the data to the database.

![Write-Back Cache](/images/write-back-cache.png)

**Advantages:**
- Extremely low write latency (write to fast memory, not slow disk)
- High write throughput — batches writes to reduce database load

**Disadvantages:**
- **Risk of data loss** — if the cache crashes before syncing, writes are lost
- More complex implementation (async sync mechanism, crash recovery)

**Best for:** Write-intensive applications where some data loss is acceptable (e.g., analytics counters, leaderboards, session data).

---

## Cache Eviction Policies

When a cache reaches capacity, it must evict existing entries to make room for new ones. The eviction policy determines which entries are removed.

| Policy | Description | Best For |
|---|---|---|
| **LRU** (Least Recently Used) | Evicts the entry that was accessed least recently | General-purpose; temporal locality workloads |
| **LFU** (Least Frequently Used) | Evicts the entry with the fewest total accesses | Workloads where some items are always popular |
| **MRU** (Most Recently Used) | Evicts the most recently accessed entry | Specific access patterns (e.g., video scrubbing) |
| **FIFO** (First In First Out) | Evicts the oldest inserted entry regardless of access | Simple queue-like caches |
| **LIFO** (Last In First Out) | Evicts the most recently inserted entry | Rarely used; specific stack-like patterns |
| **Random Replacement** | Randomly selects and evicts an entry | Simple to implement; acceptable for uniform access patterns |

**LRU is the most widely used** policy in general-purpose caches (Redis, Memcached) because it efficiently exploits temporal locality — recently accessed data is more likely to be accessed again.

---

## Cache Hierarchy (L1/L2/L3)

Similar to CPU caches, application caches operate in levels:

```
L1: Application in-process cache (fastest, smallest — e.g., HashMap in application memory)
L2: Distributed cache (fast, shared across instances — e.g., Redis cluster)
L3: Database/origin (slowest, authoritative source of truth)
```

A request checks L1 first. On miss, checks L2. On miss, fetches from L3 and populates both L2 and L1 for future requests.

---

## Distributed Cache

A single cache server is a single point of failure and has limited capacity. **Distributed caches** spread cached data across multiple nodes.

![Distributed Cache](/images/distributed-cache.png)

Key characteristics:
- **Horizontal scalability** — add nodes to increase total cache capacity
- **Consistent hashing** — determines which node stores which key (minimizes cache reshuffling when nodes join/leave)
- **Replication** — data copied to multiple nodes for fault tolerance

**Widely used distributed cache technologies:**

| Technology | Notes |
|---|---|
| [Redis](https://redis.io) | In-memory data structure store; supports strings, hashes, lists, sets, sorted sets, pub/sub, Lua scripting |
| [Memcached](https://memcached.org) | Simple key-value store; extremely fast; no persistence or advanced data types |
| [Amazon ElastiCache](https://aws.amazon.com/elasticache) | Managed Redis or Memcached on AWS |
| [Aerospike](https://aerospike.com) | Hybrid in-memory/SSD store; exceptional for real-time bidding |

---

## When NOT to Use Caching

Caching is not universally beneficial. Avoid caching when:

- **Data changes very frequently** — cache becomes stale immediately; cache miss rate approaches 100%
- **Requests have very low repetition** — random access patterns provide no cache hit benefit
- **Cache access is as slow as primary store access** — no latency benefit
- **Strong consistency is required** — cached data may be stale; if you cannot tolerate eventual consistency, avoid caching that data

---

## Content Delivery Network (CDN)

A CDN is a **geographically distributed network of servers (edge nodes)** that caches and delivers static content close to the user's physical location.

Without CDN: A user in Mumbai accessing a server in New York experiences ~200ms round-trip latency.
With CDN: The same user accesses an edge node in Mumbai — round-trip drops to ~10ms.

![CDN Architecture](/images/cdn.png)

### How CDN Works

1. The origin server holds the canonical version of content (HTML, CSS, JS, images, videos).
2. The CDN deploys **edge servers** in dozens to hundreds of global locations (PoPs — Points of Presence).
3. When a user requests a resource, DNS routes them to the nearest edge server.
4. If the edge server has the content cached, it serves it directly (cache hit).
5. If not (cache miss), the edge server fetches from origin, caches locally, and serves the user.
6. Subsequent requests from nearby users are served from the edge cache.

![CDN Map](/images/cdn-map.png)

### Push CDN vs Pull CDN

| Type | Mechanism | Best For |
|---|---|---|
| **Push CDN** | Content is explicitly pushed to CDN when created or updated | Low-traffic sites; content that changes infrequently; full control over cache |
| **Pull CDN** | CDN fetches content from origin on first request, then caches | High-traffic sites; content that changes often; self-managing cache |

### CDN Benefits

- **Reduced latency** — users served from geographically proximate edge servers
- **Reduced origin load** — edge servers absorb the majority of requests
- **DDoS protection** — CDN's distributed nature absorbs volumetric attacks
- **High availability** — content remains accessible even if origin is temporarily down

### CDN Disadvantages

- **Cost** — CDN bandwidth fees can be significant for high-traffic services
- **Cache invalidation complexity** — purging stale content across all edge nodes requires coordination
- **Geographic restrictions** — CDN providers may not have coverage in certain regions

### CDN Use Cases in System Design

| Use Case | Notes |
|---|---|
| Static assets | JS, CSS, fonts, images — ideal CDN content; rarely changes |
| Video streaming | Large files; CDN dramatically reduces origin bandwidth cost |
| API acceleration | Some CDNs can cache GET API responses at the edge |
| Dynamic content | Advanced CDNs support edge-side logic (Cloudflare Workers, Lambda@Edge) |

### Popular CDN Providers

| Provider | Notes |
|---|---|
| [Amazon CloudFront](https://aws.amazon.com/cloudfront) | Integrated with AWS services; Lambda@Edge for compute |
| [Cloudflare CDN](https://www.cloudflare.com/cdn) | Global network; DDoS protection included; Workers for edge compute |
| [Google Cloud CDN](https://cloud.google.com/cdn) | Integrated with GCP backends |
| [Fastly](https://www.fastly.com) | Real-time cache purging; used by GitHub, Stripe |

---

## Caching in System Design Interviews

When discussing caching in interviews, be prepared to address:

1. **What data to cache** — not everything should be cached; prioritize high-read, low-write data
2. **Cache invalidation strategy** — write-through, write-around, or write-back
3. **Eviction policy** — typically LRU for general workloads
4. **Cache size estimation** — use the 80/20 rule: cache 20% of data to serve ~80% of requests
5. **Cache layer placement** — in-process vs distributed vs CDN
6. **Consistency guarantees** — what staleness is acceptable? How do you handle stale reads?
