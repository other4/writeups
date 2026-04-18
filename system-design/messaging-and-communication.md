---
title: "Message Queues, Pub/Sub, WebSockets, and REST vs gRPC — Communication Patterns in System Design"
description: "A complete guide to inter-service communication patterns: message queues, publish-subscribe, long polling, WebSockets, SSE, and a comparison of REST, GraphQL, and gRPC."
author: ["name": "Rajendra Pancholi", "email": "rpancholi522@gmail.com"]
created: "2026-04-18"
updated: "2026-04-18"
thumbnail: "/images/message-broker.png"
tags: [message-queue, pub-sub, websockets, rest, grpc, graphql, system-design, communication]
keywords: ["Message queue vs pub-sub", "WebSockets vs SSE", "REST vs gRPC comparison", "Apache Kafka system design", "Long polling explained", "RabbitMQ vs Kafka"]
---

# Message Queues, Pub/Sub, WebSockets, and REST vs gRPC — Communication Patterns in System Design

How services communicate is one of the most consequential decisions in system design. The wrong communication pattern creates tight coupling, bottlenecks, and cascading failures. The right one enables loose coupling, scalability, and resilience.

This post covers the full spectrum of communication patterns — from synchronous request-response APIs to asynchronous message-driven architectures.

![Message Broker](/images/message-broker.png)

---

## Synchronous vs Asynchronous Communication

| Type | Description | When to Use |
|---|---|---|
| **Synchronous** | Caller waits for a response before proceeding (HTTP, gRPC) | When the result is needed immediately; user-facing operations |
| **Asynchronous** | Caller sends a message and continues without waiting (queues, events) | Background processing, decoupling services, handling load spikes |

---

## Message Queues

A message queue provides **asynchronous point-to-point communication** between services. Producers send messages to a queue; consumers read messages from it.

![Message Queue](/images/message-queue.png)

### How It Works

1. A **producer** sends a message to the queue (including the job payload and metadata).
2. The message is **stored in the queue** until a consumer is available.
3. A **consumer** reads the message, processes it, and deletes it from the queue.
4. Each message is typically consumed by **exactly one consumer** (point-to-point).

### Key Features

| Feature | Description |
|---|---|
| **At-Least-Once Delivery** | Queue retries delivery if consumer fails to acknowledge; may produce duplicates |
| **Exactly-Once Delivery** | Deduplication ensures each message is processed exactly once (FIFO queues) |
| **FIFO Ordering** | Messages delivered in the order they were sent |
| **Dead-Letter Queue (DLQ)** | Messages that fail to process after N retries are moved to a DLQ for inspection |
| **Scheduled Delivery** | Messages can be delayed for a specified duration before becoming visible |
| **Backpressure** | Queue size limits protect consumers from being overwhelmed; producers receive 503 when queue is full |

### Advantages
- **Decoupling** — producers and consumers are independent; neither needs to know about the other's availability
- **Resilience** — if the consumer crashes, messages wait in the queue until it recovers (no data loss)
- **Load leveling** — queue buffers traffic spikes; consumers process at their own pace
- **Scalability** — add more consumer instances to increase throughput

### Popular Message Queue Solutions

| Solution | Notes |
|---|---|
| [Amazon SQS](https://aws.amazon.com/sqs) | Managed; standard (at-least-once) and FIFO queues |
| [RabbitMQ](https://www.rabbitmq.com) | Open-source; flexible routing; supports multiple protocols |
| [ActiveMQ](https://activemq.apache.org) | JMS-based; enterprise feature set |
| [ZeroMQ](https://zeromq.org) | Lightweight; embedded messaging library |

---

## Publish-Subscribe (Pub/Sub)

In pub/sub, a **publisher sends messages to a topic**; all subscribers to that topic receive the message. Unlike point-to-point queues, pub/sub enables **fan-out** — one message reaching many consumers simultaneously.

![Publish-Subscribe](/images/publish-subscribe.png)

### How It Works

1. Publishers send messages to a **topic** (a named channel).
2. Subscribers register interest in one or more topics.
3. The message broker **delivers the message to all active subscribers** simultaneously.
4. Each subscriber processes the message independently.

### Pub/Sub vs Message Queue

| Aspect | Message Queue | Pub/Sub |
|---|---|---|
| Delivery | One message → one consumer | One message → many consumers |
| Relationship | Point-to-point | Fan-out |
| Consumer awareness | Producers target a specific queue | Publishers are unaware of subscribers |
| Use case | Task distribution, job queues | Event notifications, real-time feeds |

### Features
- **Filtering** — subscribers can register interest in only a subset of messages (by attributes, content, type)
- **Durability** — multiple copies stored across servers to prevent message loss
- **Fanout** — one event triggers parallel processing by multiple independent services

### Popular Pub/Sub Solutions

| Solution | Notes |
|---|---|
| [Apache Kafka](https://kafka.apache.org) | Distributed log; extremely high throughput; persistent message storage; replay capability |
| [Google Cloud Pub/Sub](https://cloud.google.com/pubsub) | Managed; at-least-once delivery; push and pull modes |
| [Amazon SNS](https://aws.amazon.com/sns) | Managed; push notifications to SQS, Lambda, HTTP, email, SMS |
| [NATS](https://nats.io) | Lightweight; extremely fast; cloud-native |
| [RabbitMQ](https://www.rabbitmq.com) | Supports both queue and pub/sub patterns via exchanges |

---

## Long Polling, WebSockets, and Server-Sent Events

Traditional HTTP is **request-driven** — the client always initiates. For real-time applications, the server needs to push data to clients. Three patterns address this.

### Long Polling

The client sends an HTTP request; the server **holds the connection open** until new data is available or a timeout occurs. Once data is returned, the client immediately sends another request.

![Long Polling](/images/long-polling.png)

**Pros:** Simple to implement; works everywhere HTTP works; no special infrastructure.
**Cons:** Each "push" requires a new HTTP connection; not truly scalable at high concurrency; increased server connection overhead.

**Use cases:** Low-frequency notifications, simple chat applications, when WebSocket infrastructure is unavailable.

### WebSockets

WebSockets establish a **persistent, full-duplex TCP connection** between client and server, allowing both to send data at any time without re-establishing a connection.

![WebSockets](/images/websockets.png)

**Handshake:** The client sends an HTTP request with an `Upgrade: websocket` header. If the server accepts, the connection is upgraded to WebSocket protocol (`ws://` or `wss://`).

**Pros:**
- True full-duplex — both client and server send independently
- Very low latency — no connection overhead per message
- Efficient for high-frequency updates (stock prices, gaming, chat)

**Cons:**
- Terminated connections aren't automatically recovered (client must reconnect)
- Stateful connections complicate horizontal scaling (need sticky sessions or shared connection state)
- Older environments may have proxy/firewall issues with long-lived connections

**Use cases:** Real-time chat, live gaming, collaborative editing, financial tickers, real-time dashboards.

### Server-Sent Events (SSE)

SSE establishes a **persistent, unidirectional HTTP connection** — the server streams events to the client, but the client cannot send data back over the same connection.

![Server-Sent Events](/images/server-sent-events.png)

**Pros:**
- Simpler than WebSockets — standard HTTP, works through proxies and firewalls
- Built-in automatic reconnection
- Native browser EventSource API

**Cons:**
- Unidirectional — cannot receive messages from client on same connection
- Limited to text data (no binary)
- Browser connection limit (typically 6 per domain)

**Use cases:** News feeds, live score updates, server-side push notifications, log streaming.

### Comparison

| Feature | Long Polling | WebSockets | SSE |
|---|---|---|---|
| Directionality | Request-response | Full-duplex | Server-to-client only |
| Protocol | HTTP | ws:// / wss:// | HTTP |
| Latency | Moderate | Low | Low |
| Binary data | No | Yes | No |
| Complexity | Low | Medium | Low |
| Auto-reconnect | No (must re-implement) | No | Yes |
| Best for | Infrequent updates | High-frequency, bidirectional | Server push, notifications |

---

## REST vs GraphQL vs gRPC

These three API design approaches represent different philosophies for how services expose their capabilities.

### REST (Representational State Transfer)

REST is an **architectural style** for designing networked APIs using HTTP verbs (GET, POST, PUT, PATCH, DELETE) and resource-based URLs.

**Core constraints:**
- Uniform interface — consistent resource URLs and HTTP verb semantics
- Stateless — no client state stored on server between requests
- Cacheable — responses explicitly declare cacheability
- Client-server separation

**Advantages:** Simple, widely understood, excellent caching, human-readable.

**Disadvantages:** Over-fetching (client gets more data than needed) and under-fetching (multiple round trips to assemble a view).

**Best for:** Public APIs, CRUD services, general-purpose APIs.

### GraphQL

GraphQL is a **query language and runtime** where the client specifies exactly which fields it needs. Developed by Facebook, open-sourced in 2015.

```graphql
# Client requests exactly what it needs
{
  user(id: "123") {
    name
    email
    posts {
      title
    }
  }
}
```

**Advantages:**
- No over-fetching or under-fetching — client gets exactly what it asks for
- Single endpoint for all operations
- Strongly typed schema acts as documentation
- Excellent for complex, graph-like data models

**Disadvantages:**
- N+1 query problem requires DataLoader batching
- Caching is more complex (responses are query-specific)
- Server-side complexity is higher (resolver implementation)

**Best for:** Mobile apps (bandwidth-sensitive), complex data graphs, BFF pattern.

### gRPC

gRPC is a **high-performance RPC framework** from Google using Protocol Buffers for serialization over HTTP/2.

```protobuf
service UserService {
  rpc GetUser (GetUserRequest) returns (User);
  rpc StreamUsers (Empty) returns (stream User);
}
```

**Advantages:**
- Extremely high performance — binary serialization is ~5x smaller than JSON
- Bi-directional streaming — server, client, or bidirectional streaming supported
- Strongly typed contracts — .proto files generate clients in 10+ languages
- Built-in code generation

**Disadvantages:**
- Limited browser support (requires gRPC-Web proxy for browser clients)
- Binary format is not human-readable — harder to debug
- Steeper learning curve

**Best for:** Internal microservice-to-microservice communication, high-throughput services, polyglot environments.

### Comparison Table

| Aspect | REST | GraphQL | gRPC |
|---|---|---|---|
| Coupling | Low | Medium | High |
| Chattiness | High (multiple endpoints) | Low (single query) | Medium |
| Performance | Good | Good | Excellent |
| Caching | Excellent (HTTP-native) | Complex (custom) | Complex (custom) |
| Browser support | Excellent | Excellent | Limited (gRPC-Web) |
| Schema/contract | Optional (OpenAPI) | Required (.graphql) | Required (.proto) |
| Code generation | Mediocre | Good | Excellent |
| Best for | Public APIs, CRUD | Complex queries, mobile | Internal services |

---

## Event Sourcing

Instead of storing current state, event sourcing stores the **complete history of events** that produced that state. To reconstruct current state, replay all events.

![Event Sourcing](/images/event-sourcing.png)

**Advantages:**
- Complete audit log of all state changes
- Can replay events to reconstruct state at any point in time
- Enables temporal queries ("what was the state at 3pm yesterday?")
- Natural fit with CQRS — event log is the write model

**Disadvantages:**
- Large event stores — years of events can become enormous
- Querying current state requires replaying all events (mitigated with snapshots)
- Schema evolution of events is complex

**Use cases:** Financial transaction systems, auditing requirements, collaborative editing systems.

---

## Service Discovery

In a dynamic microservices environment, service instances start and stop constantly. **Service discovery** enables services to find each other without hardcoded IP addresses.

### Client-Side Discovery
The client queries a service registry (e.g., Consul, Etcd) and selects an instance, then calls it directly.

### Server-Side Discovery
The client makes a request to a load balancer or router, which queries the registry and forwards to an available instance.

### Service Registry
A database of available service instances and their addresses. Instances register on startup and deregister on shutdown.

**Examples:** [Consul](https://www.consul.io), [etcd](https://etcd.io), [Apache Zookeeper](https://zookeeper.apache.org), [Eureka](https://github.com/Netflix/eureka) (Netflix)
