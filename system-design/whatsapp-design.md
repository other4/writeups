---
title: "System Design Case Study — WhatsApp (Instant Messaging at Scale)"
description: "A complete system design for building a WhatsApp-like instant messaging service: real-time messaging, read receipts, last seen, push notifications, media storage, and multi-region architecture."
author: ["name": "Rajendra Pancholi", "email": "rpancholi522@gmail.com"]
created: "2026-04-18"
updated: "2026-04-18"
thumbnail: "/images/whatsapp-system-design.png"
tags: [system-design, whatsapp, messaging, websockets, case-study, scalability]
keywords: ["WhatsApp system design", "Design instant messaging service", "Real-time chat system design", "WebSockets messaging architecture", "Push notification system design"]
---

# System Design Case Study — WhatsApp (Instant Messaging at Scale)

WhatsApp connects over 2 billion users across 180 countries, processing 100 billion messages per day. Designing a system at this scale requires careful decisions about real-time communication protocols, message delivery guarantees, media storage, and multi-region infrastructure.

![WhatsApp System Design](/images/whatsapp-system-design.png)

---

## Requirements

### Functional Requirements
- One-on-one chat between users
- Group chats (up to 100 participants)
- File sharing: images, videos, documents
- Sent, Delivered, and Read receipts (double-tick system)
- Online presence and last seen timestamps
- Push notifications for offline users

### Non-Functional Requirements
- High availability with minimal latency (< 100ms message delivery)
- Messages must not be lost — at-least-once delivery
- Horizontally scalable to support 50M+ daily active users
- End-to-end encryption (architectural consideration)

### Extended Requirements
- Voice and video calls (not covered in depth here)
- Message search
- Broadcast lists

---

## Capacity Estimation

- **50 million daily active users (DAU)**
- Each user sends 40 messages/day to ~4 different people

```
Daily messages: 50M × 40 = 2 billion messages/day
RPS: 2 billion / 86,400 = ~24,000 messages/second
```

**Media files (5% of messages):**
```
100 million media files/day × 100 KB average = 10 TB/day
```

**Total storage for 10 years:**
```
(10 TB media + 0.2 TB text) × 365 × 10 = ~38 PB
```

**Bandwidth:**
```
10.2 TB/day ÷ 86,400s = ~120 MB/second ingress
```

| Metric | Estimate |
|---|---|
| Daily active users | 50 million |
| Messages/second | ~24,000 |
| Storage/day | ~10.2 TB |
| Storage/10 years | ~38 PB |
| Bandwidth | ~120 MB/s |

---

## Data Model

### `users` table
| Column | Type |
|---|---|
| `id` | UUID |
| `phone_number` | VARCHAR (unique) |
| `name` | VARCHAR |
| `last_seen` | TIMESTAMP |
| `profile_pic_url` | VARCHAR |

### `messages` table
| Column | Type | Description |
|---|---|---|
| `id` | UUID | Primary key |
| `chat_id` | UUID | Associated chat or group |
| `sender_id` | UUID | Sender user ID |
| `type` | ENUM | text, image, video, document, audio |
| `content` | TEXT | Message body or media URL |
| `sent_at` | TIMESTAMP | When sent by sender |
| `delivered_at` | TIMESTAMP | When delivered to recipient device |
| `seen_at` | TIMESTAMP | When recipient opened the chat |

### `chats` table (private chats between two users)
| Column | Type |
|---|---|
| `id` | UUID |
| `created_at` | TIMESTAMP |

### `users_chats` table (N:M mapping)
| Column | Type |
|---|---|
| `user_id` | UUID |
| `chat_id` | UUID |

### `groups` table
| Column | Type |
|---|---|
| `id` | UUID |
| `name` | VARCHAR |
| `created_by` | UUID |
| `created_at` | TIMESTAMP |

### `users_groups` table (N:M mapping)
| Column | Type |
|---|---|
| `user_id` | UUID |
| `group_id` | UUID |
| `joined_at` | TIMESTAMP |
| `role` | ENUM (admin, member) |

**Database Choice:** Apache Cassandra or HBase for the messages table (high write throughput, time-range queries, natural horizontal sharding). PostgreSQL for user and chat metadata.

---

## API Design

```
// Get all chats/groups for a user
GET /users/{userID}/chats
Response: [{ chatID, lastMessage, unreadCount, participants }]

// Get messages in a chat
GET /chats/{chatID}/messages?before={timestamp}&limit=50
Response: [{ messageID, senderID, content, type, sentAt, deliveredAt, seenAt }]

// Send a message
POST /chats/{chatID}/messages
Body: { senderID, content, type }
Response: { messageID, sentAt }

// Create a group
POST /groups
Body: { name, memberIDs }
Response: { groupID }

// Join/leave a group
POST /groups/{groupID}/members
DELETE /groups/{groupID}/members/{userID}
```

---

## Architecture

### Microservices

| Service | Responsibility |
|---|---|
| **User Service** | Authentication, user profiles, phone number registration |
| **Chat Service** | WebSocket connections, real-time message delivery |
| **Notification Service** | Push notifications (FCM/APNs) for offline users |
| **Presence Service** | Online status, last seen tracking |
| **Media Service** | Upload, process, and serve media files |
| **Group Service** | Group creation, membership management |

Inter-service communication via **gRPC** for low latency. Service discovery via Consul or Kubernetes DNS.

---

## Real-Time Messaging — WebSocket Architecture

The pull model (HTTP polling) is not viable for messaging — it creates massive unnecessary load and has high latency. The push model via **WebSockets** is the right choice.

![WebSocket Messaging](/images/websockets.png)

### How message delivery works:

1. **Sender** types a message and hits send.
2. **Chat Service** receives the message over the sender's WebSocket connection.
3. Chat Service stores the message in the database (with `delivered_at = null`, `seen_at = null`).
4. Chat Service looks up the **recipient's active WebSocket connection** (via a connection registry in Redis).
5. If recipient is **online**: push the message directly over WebSocket → mark `delivered_at = now()`.
6. If recipient is **offline**: enqueue a notification event in the message queue → Notification Service sends FCM/APNS push notification.
7. When recipient opens the chat → mark `seen_at = now()` → push read receipt back to sender via WebSocket.

### Connection Registry (Redis)

When a user connects via WebSocket, register their connection:
```
SET connection:{userID} {chatServerID} EX 3600
```

When the Chat Service needs to deliver a message, it looks up which Chat Server hosts the recipient's connection, then routes the message to that server.

### Message Queue for Reliability

Even with WebSockets, message delivery must be reliable. Messages are written to a message queue (Kafka) before delivery. The Chat Service consumes from Kafka to ensure messages are processed even if the delivery server restarts.

---

## Read Receipts (Sent / Delivered / Seen)

WhatsApp's iconic tick system:

| State | Indicator | Mechanism |
|---|---|---|
| **Sent** | Single grey tick | Message stored in server DB; `sent_at` set |
| **Delivered** | Double grey tick | Message delivered to recipient device; `delivered_at` set; ACK sent to sender |
| **Seen** | Double blue tick | Recipient opens the chat; `seen_at` set; read receipt pushed to sender via WebSocket |

**ACK mechanism:** When the recipient's device receives the message, it sends an acknowledgment back to the Chat Service, which updates `delivered_at` and pushes the delivery receipt to the sender.

---

## Presence Service — Last Seen

The Presence Service tracks the **last active timestamp** of every user.

**Heartbeat mechanism:** The client periodically sends a heartbeat ping every 30 seconds while active. The Presence Service updates a Redis cache:

```
SET presence:{userID} {timestamp} EX 60
```

If no heartbeat is received within 60 seconds, the user is considered offline and `last_seen` is updated in the database.

**Lazy evaluation alternative:** Track the user's last action timestamp. When another user requests someone's presence, if their last action was more than 30 seconds ago, show them as offline with the last_seen timestamp.

---

## Push Notifications

When a message recipient is offline, the Chat Service enqueues a notification event:

1. **Chat Service** → publishes event to **Amazon SQS / RabbitMQ**
2. **Notification Service** consumes the event
3. Checks device platform (iOS / Android / Web)
4. Routes to **Apple Push Notification Service (APNs)** or **Firebase Cloud Messaging (FCM)**
5. Push notification delivered to device

**Payload includes:** Sender name, message preview (if end-to-end encryption not enabled), chat ID for deep linking.

![Notification Flow](/images/message-queue.png)

---

## Media Handling

Media files (images, videos, documents) are not transmitted through the chat server. Instead:

1. **Sender** uploads media directly to the **Media Service**.
2. Media Service stores the file in **Amazon S3** (or equivalent object storage).
3. Media Service returns a URL for the uploaded file.
4. **Sender** sends a message with `type=image` and `content=media_url`.
5. **Recipient** downloads the media from the URL (served via **CloudFront CDN** for low latency).

**Media processing:** Images are compressed and resized. Videos are transcoded to web-compatible formats. Thumbnails are generated for preview.

**WhatsApp deletes media from servers** after it has been downloaded — this reduces storage costs significantly.

---

## Group Chat Architecture

For group chats (up to 100 members):

1. Sender sends one message to the Group Service.
2. Group Service fans out the message to all group members' Chat Service connections.
3. For offline members, fan-out events are queued in the Notification Service.

**Fan-out challenge at scale:** A group with 100 members means one message generates 99 deliveries. For groups with very large memberships (broadcast channels), this fan-out must be handled asynchronously via Kafka to avoid blocking.

---

## Advanced Architecture

![WhatsApp Advanced Design](/images/whatsapp-advanced-design.png)

### Data Partitioning
- Shard `messages` table by `chat_id` — ensures all messages for a chat reside on the same shard (efficient retrieval)
- Consistent hashing for shard assignment

### Caching
- Cache recent messages (last 20 per chat) in Redis — reduces database load for the common case
- LRU eviction policy

### API Gateway
Since the system uses both HTTP and WebSocket protocols, an API Gateway that supports both is essential. AWS API Gateway supports HTTP + WebSocket. Alternatively, NGINX or Envoy can handle both.

---

## Bottleneck Resolution

| Bottleneck | Solution |
|---|---|
| Single Chat Service crash | Multiple instances; WebSocket session recovery |
| Message loss during server crash | Kafka ensures durability; consumer retries |
| Media storage cost | Compress + delete after download; lifecycle policies |
| Group message fan-out | Async Kafka-based fan-out for large groups |
| Last seen accuracy | Heartbeat with Redis; fallback to last action timestamp |
| Notification delivery failure | Dead-letter queue for failed pushes; retry with exponential backoff |

---

## Summary

| Component | Technology |
|---|---|
| Real-time messaging | WebSockets (Chat Service) |
| Message broker | Apache Kafka |
| Primary database | Apache Cassandra (messages), PostgreSQL (users/groups) |
| Cache | Redis (connections, presence, recent messages) |
| Media storage | Amazon S3 + CloudFront CDN |
| Push notifications | FCM (Android) + APNs (iOS) |
| API Gateway | AWS API Gateway / NGINX |
| Service discovery | Consul / Kubernetes DNS |
