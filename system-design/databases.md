---
title: "Databases in System Design — SQL, NoSQL, Replication, Sharding, and ACID vs BASE"
description: "A comprehensive guide to database selection in system design: relational vs non-relational databases, replication strategies, sharding, CAP theorem, ACID and BASE consistency models."
author: ["name": "Rajendra Pancholi", "email": "rpancholi522@gmail.com"]
created: "2026-04-18"
updated: "2026-04-18"
thumbnail: "/images/databases.png"
tags: [databases, sql, nosql, sharding, replication, cap-theorem, system-design]
keywords: ["SQL vs NoSQL system design", "Database sharding explained", "CAP theorem", "ACID vs BASE", "Database replication master slave", "When to use NoSQL"]
---

# Databases in System Design — SQL, NoSQL, Replication, Sharding, and ACID vs BASE

The database layer is often the most critical — and most constrained — component in any large-scale system. Choosing the wrong database model, replication strategy, or partitioning scheme can create bottlenecks that are extremely difficult and costly to fix later.

This guide covers the complete database landscape: relational vs non-relational models, consistency guarantees, replication, sharding, and how to choose the right database for a given system design problem.

![Database Types](/images/databases.png)

---

## SQL (Relational) Databases

A relational database stores data in **tables with rows and columns**, with pre-defined relationships between tables enforced by foreign keys. SQL databases follow the ACID consistency model.

### Key Characteristics

- **Structured schema** — table structure must be defined before data is inserted; schema changes require migrations
- **Relationships** — data integrity enforced via primary keys, foreign keys, and join operations
- **ACID transactions** — full transactional support with atomicity, consistency, isolation, and durability
- **SQL query language** — powerful, standardized querying with JOINs, aggregations, subqueries

### Materialized Views

A materialized view is a **pre-computed result set** stored as a physical table, derived from a query. It provides dramatically faster reads for complex aggregations at the cost of staleness — the view must be periodically refreshed.

Use cases: dashboard aggregations, reporting queries, pre-joined datasets.

### Advantages

- Simple, mature, well-understood data model
- Strong data consistency and integrity
- Powerful querying with JOINs across related tables
- ACID transactions with rollback support
- Excellent ecosystem: tooling, ORMs, monitoring

### Disadvantages

- **Horizontal scaling is difficult** — sharding relational databases is complex
- **Schema rigidity** — adding or changing columns requires migrations, which can be dangerous on large tables
- **JOIN performance** — complex JOINs across large tables are expensive
- **Object-relational impedance mismatch** — mapping OOP models to relational tables requires an ORM

### Popular SQL Databases

| Database | Notes |
|---|---|
| [PostgreSQL](https://www.postgresql.org) | Most feature-rich open-source SQL DB; JSON support, JSONB, full-text search |
| [MySQL](https://www.mysql.com) | Widely deployed; excellent read performance |
| [MariaDB](https://mariadb.org) | MySQL fork; open-source friendly |
| [Amazon Aurora](https://aws.amazon.com/rds/aurora) | MySQL/PostgreSQL compatible; up to 5x faster; auto-scaling storage |

---

## NoSQL (Non-Relational) Databases

NoSQL databases abandon the rigid relational model in favor of flexible schemas and horizontal scalability. They follow the BASE consistency model rather than ACID.

### Document Databases

Store data as **semi-structured documents** (JSON, BSON) where each document can have a different structure. No foreign keys — related data is embedded within documents.

**Best for:** Content management, user profiles, product catalogs, applications with variable schemas.

**Examples:** [MongoDB](https://www.mongodb.com), [Amazon DocumentDB](https://aws.amazon.com/documentdb), [CouchDB](https://couchdb.apache.org)

### Key-Value Stores

The simplest NoSQL model — data is stored and retrieved by a **unique key** with an opaque value. Extremely fast for simple lookups but cannot perform complex queries.

**Best for:** Session storage, caching, shopping carts, feature flags, user preferences.

**Examples:** [Redis](https://redis.io), [Memcached](https://memcached.org), [Amazon DynamoDB](https://aws.amazon.com/dynamodb)

### Graph Databases

Stores data as **nodes (entities) and edges (relationships)**, optimized for traversing complex interconnected data. Relationship queries that would require dozens of JOINs in SQL can be expressed naturally and executed efficiently.

**Best for:** Social networks, fraud detection, recommendation engines, knowledge graphs.

**Examples:** [Neo4j](https://neo4j.com), [Amazon Neptune](https://aws.amazon.com/neptune), [ArangoDB](https://www.arangodb.com)

### Time Series Databases

Optimized for **time-stamped sequential data** — storing and querying data points indexed by time. Provide efficient compression and fast range queries over time windows.

**Best for:** IoT sensor data, application metrics, financial tick data, server monitoring.

**Examples:** [InfluxDB](https://www.influxdata.com), [Apache Druid](https://druid.apache.org)

### Wide-Column Stores

Store data in **column families** rather than rows. Each row can have a different set of columns. Designed for massive datasets with high write throughput across distributed nodes.

**Best for:** Time-series data at scale, event logging, analytics at petabyte scale.

**Examples:** [Apache Cassandra](https://cassandra.apache.org), [Google Bigtable](https://cloud.google.com/bigtable), [ScyllaDB](https://www.scylladb.com)

---

## SQL vs NoSQL — Decision Guide

| Criteria | Choose SQL | Choose NoSQL |
|---|---|---|
| Data structure | Structured with defined relationships | Semi-structured or unstructured |
| Schema | Fixed, rarely changing | Dynamic, frequently evolving |
| Consistency | Strong (ACID) required | Eventual consistency acceptable |
| Scalability | Vertical (or complex horizontal sharding) | Horizontal (built-in) |
| Query complexity | Complex JOINs and aggregations | Simple key-value or document queries |
| Transactions | Multi-row ACID transactions required | Single-document/single-key operations |
| Team expertise | SQL expertise available | NoSQL expertise available |

---

## ACID Consistency Model

ACID is the set of properties that guarantee reliable processing of database transactions in relational databases.

| Property | Meaning |
|---|---|
| **Atomicity** | A transaction either fully completes or fully rolls back — no partial success |
| **Consistency** | The database moves from one valid state to another; all integrity constraints are upheld |
| **Isolation** | Concurrent transactions execute as if they ran sequentially — no interference |
| **Durability** | Once committed, a transaction's effects persist even through system crashes |

ACID databases are ideal for financial systems, inventory management, and any domain where data correctness cannot be compromised.

---

## BASE Consistency Model

BASE is the NoSQL alternative to ACID, trading strict consistency for availability and scalability.

| Property | Meaning |
|---|---|
| **Basically Available** | The system appears to work most of the time, even under partial failure |
| **Soft State** | The state of the system may change over time even without new inputs (convergence to consistency) |
| **Eventually Consistent** | The system will become consistent over time, but reads may return stale data temporarily |

BASE databases accept that in a distributed system at massive scale, strict consistency requires unacceptable latency or availability trade-offs.

---

## CAP Theorem

The CAP theorem states that a **distributed system can only provide two of three guarantees** simultaneously:

![CAP Theorem](/images/cap-theorem.png)

| Property | Meaning |
|---|---|
| **Consistency (C)** | All clients see the same data at the same time regardless of which node they connect to |
| **Availability (A)** | Every request receives a response (not necessarily the most recent data) |
| **Partition Tolerance (P)** | The system continues functioning despite network partitions (message loss between nodes) |

Since network partitions are unavoidable in any distributed system (hardware fails, networks partition), **P is always required**. The real choice is between C and A:

| Trade-off | Description | Examples |
|---|---|---|
| **CP** (Consistency + Partition Tolerance) | System refuses to serve stale data; goes offline during partition | MongoDB, Apache HBase, Zookeeper |
| **AP** (Availability + Partition Tolerance) | System serves potentially stale data; always responds | Apache Cassandra, CouchDB, DynamoDB |
| **CA** (Consistency + Availability) | Only achievable without network partitions (single server or LAN) | PostgreSQL (single node), MySQL (single node) |

---

## Database Replication

Replication copies data across multiple database servers to improve reliability, read performance, and fault tolerance.

### Master-Slave Replication

One **master** node handles all writes. Changes are replicated to one or more **slave** (replica) nodes, which handle read queries.

![Master-Slave Replication](/images/master-slave-replication.png)

**Advantages:**
- Read scalability — scale reads by adding more slaves
- Backups on slaves don't impact master performance
- Slaves can be promoted to master on failure

**Disadvantages:**
- Single write endpoint is a bottleneck and single point of failure for writes
- Replication lag — slaves may serve slightly stale data
- Promoting a slave to master requires reconfiguration

### Master-Master Replication

Multiple nodes each accept both reads and writes. Changes are synchronized between all masters.

![Master-Master Replication](/images/master-master-replication.png)

**Advantages:**
- No single write bottleneck
- Can survive master failure without manual promotion

**Disadvantages:**
- Conflict resolution is complex (what if two masters write conflicting values simultaneously?)
- Increased write latency due to synchronization overhead

### Synchronous vs Asynchronous Replication

| Type | Behavior | Trade-off |
|---|---|---|
| **Synchronous** | Write only acknowledged after all replicas confirm | Zero data loss, but higher write latency |
| **Asynchronous** | Write acknowledged after primary write; replicas updated later | Lower latency, but risk of data loss if primary fails before replication |

---

## Database Sharding

Sharding (horizontal partitioning) splits data across multiple database instances, each holding a **subset (shard)** of the total data. Each shard has the same schema but different rows.

![Database Sharding](/images/sharding.png)

### Partitioning Criteria

| Strategy | Description | Pros | Cons |
|---|---|---|---|
| **Hash-Based** | Apply a hash function to a key; use result modulo N to select shard | Even distribution | Expensive to add/remove shards (re-hashing) |
| **Range-Based** | Split by value ranges (e.g., users A-M → Shard 1, N-Z → Shard 2) | Easy range queries | Hot spots if data is skewed |
| **List-Based** | Assign specific values to specific shards (e.g., by country) | Logical partitioning | Manual management |
| **Composite** | Combine two or more strategies | Flexible | Complex |

### Consistent Hashing

Consistent hashing solves the key re-distribution problem in hash-based sharding. Servers and data keys are mapped onto a circular ring. When a server is added or removed, only `K/N` keys need to be redistributed (where K = total keys, N = number of nodes), rather than all keys.

**Virtual nodes** are used to ensure even distribution across the ring, preventing hot spots.

### Advantages of Sharding

- Massive horizontal scalability — add shards to increase capacity
- Query performance improves — each shard handles a smaller dataset
- Fault isolation — a failure in one shard does not affect others

### Disadvantages of Sharding

- Cross-shard queries are expensive or impossible (JOINs across shards require application-level merging)
- Rebalancing shards when adding nodes is complex
- Increased operational complexity
- Transactions spanning multiple shards require distributed transaction protocols (2PC)

---

## Database Indexes

Indexes are data structures that allow the database engine to find rows **without scanning every row in the table**. They work like a book index — a sorted reference structure pointing to where data lives.

**Dense Index:** An index entry for every row. Faster lookups. More memory.
**Sparse Index:** An index entry for only some rows. Less memory. Requires a scan within indexed range.

**Index trade-off:** Indexes speed up reads but slow down writes (the index must be updated on every INSERT, UPDATE, DELETE) and consume additional storage.

---

## Normalization vs Denormalization

**Normalization** organizes data to minimize redundancy by splitting data into multiple related tables. Follows normal forms (1NF, 2NF, 3NF, BCNF).

**Denormalization** intentionally introduces redundancy by duplicating data across tables to optimize read performance and avoid expensive JOINs.

| Approach | Read Performance | Write Performance | Storage | Consistency |
|---|---|---|---|---|
| Normalized | Slower (requires JOINs) | Faster (update in one place) | Less | Better |
| Denormalized | Faster (fewer JOINs) | Slower (update multiple copies) | More | Worse |

In high-read systems (social media feeds, analytics dashboards), denormalization is often a deliberate performance optimization.
