---
title: "System Design Case Study — Twitter (Social Media at Scale)"
description: "A comprehensive system design for Twitter: newsfeed generation, fan-out strategies, trending topics, search with Elasticsearch, and handling 1 billion daily active users."
author: ["name": "Rajendra Pancholi", "email": "rpancholi522@gmail.com"]
created: "2026-04-18"
updated: "2026-04-18"
thumbnail: "/images/twitter-sytem-desing.png"
tags: [system-design, twitter, social-media, newsfeed, elasticsearch, case-study]
keywords: ["Twitter system design", "Newsfeed system design", "Fan-out on write vs read", "Social media architecture", "Elasticsearch trending topics", "System design interview Twitter"]
---

# System Design Case Study — Twitter (Social Media at Scale)

Twitter serves over 200 million daily active users, each generating a personalized feed from the people they follow. Designing the newsfeed generation pipeline, real-time trending topics, and global media delivery at this scale presents some of the most interesting distributed systems challenges.

![Twitter System Design](/images/twitter-sytem-desing.png)

---

## Requirements

### Functional Requirements
- Post tweets (text up to 280 characters, images, videos)
- Follow and unfollow other users
- Home timeline / newsfeed: chronological feed of tweets from followed users
- Search tweets by keyword, hashtag, or user
- Like (favorite) and retweet tweets
- Push notifications for mentions, follows, likes

### Non-Functional Requirements
- High availability with minimal latency
- Eventually consistent newsfeed is acceptable
- Read-heavy system (newsfeed reads >> tweet writes)
- Support for 200M DAU with 1 billion total users

### Extended Requirements
- Trending topics and hashtags
- Analytics and metrics
- Verified user system and content moderation

---

## Capacity Estimation

- **200 million DAU**, each posting ~5 tweets/day

```
Daily tweets: 200M × 5 = 1 billion tweets/day
Write RPS: 1 billion / 86,400 = ~12,000 tweets/second
```

**Media (10% of tweets have media, avg 50 KB):**
```
100 million media files × 50 KB = 5 TB/day
```

**10-year storage:**
```
(5 TB + 0.1 TB) × 365 × 10 ≈ 19 PB
```

**Read amplification:** Each tweet is read by all followers. If average user has 200 followers:
```
12,000 writes/s × 200 followers = 2.4 million fan-out operations/second
```

This is why newsfeed fan-out is the hardest part of Twitter's architecture.

| Metric | Estimate |
|---|---|
| DAU | 200 million |
| Tweets/second | ~12,000 |
| Storage/day | ~5.1 TB |
| Storage/10 years | ~19 PB |
| Bandwidth | ~60 MB/s |

---

## Data Model

### `users` table
| Column | Type |
|---|---|
| `id` | UUID |
| `username` | VARCHAR (unique, indexed) |
| `email` | VARCHAR |
| `bio` | TEXT |
| `follower_count` | INT |
| `following_count` | INT |
| `created_at` | TIMESTAMP |

### `tweets` table
| Column | Type |
|---|---|
| `id` | UUID |
| `user_id` | UUID |
| `content` | VARCHAR(280) |
| `type` | ENUM (text, image, video, retweet) |
| `media_url` | VARCHAR |
| `retweet_of` | UUID (nullable, FK to tweets.id) |
| `like_count` | INT |
| `retweet_count` | INT |
| `created_at` | TIMESTAMP (indexed) |

### `followers` table
| Column | Type |
|---|---|
| `follower_id` | UUID |
| `followee_id` | UUID |
| `created_at` | TIMESTAMP |

### `feeds` table (pre-generated newsfeed)
| Column | Type |
|---|---|
| `user_id` | UUID |
| `tweet_id` | UUID |
| `score` | FLOAT (ranking score) |
| `created_at` | TIMESTAMP |

### `favorites` table
| Column | Type |
|---|---|
| `user_id` | UUID |
| `tweet_id` | UUID |
| `created_at` | TIMESTAMP |

---

## API Design

```
// Post a tweet
POST /tweets
Body: { content, mediaURL? }
Response 201: { tweetID, shortURL }

// Follow a user
POST /users/{userID}/follow
Response 200: { success: true }

// Unfollow a user
DELETE /users/{userID}/follow
Response 200: { success: true }

// Get home timeline (newsfeed)
GET /timeline?cursor={timestamp}&limit=20
Response: [{ tweet, user, likeCount, retweetCount, liked, retweeted }]

// Search tweets
GET /search?q={query}&type=tweets&cursor={cursor}
Response: [{ tweet, user, relevanceScore }]

// Like a tweet
POST /tweets/{tweetID}/like
Response 200: { likeCount }

// Retweet
POST /tweets/{tweetID}/retweet
Response 201: { tweetID }
```

---

## Architecture

### Core Services

| Service | Responsibility |
|---|---|
| **User Service** | Authentication, user profiles, follow relationships |
| **Tweet Service** | Tweet creation, likes, retweets |
| **Feed Service** | Newsfeed generation and delivery |
| **Search Service** | Full-text search via Elasticsearch |
| **Media Service** | Upload, transcode, and serve media files |
| **Notification Service** | Push notifications for interactions |
| **Analytics Service** | Metrics, trending topics, user analytics |

---

## Newsfeed — The Hard Problem

The newsfeed is Twitter's hardest engineering challenge. It requires aggregating tweets from all accounts a user follows, ranking them, and serving a personalized result — for 200M users.

### Feed Generation

For user A's feed:
1. Fetch IDs of all users A follows (could be thousands for power users)
2. Fetch recent tweets from each followed user
3. Apply a **ranking algorithm** to score and sort tweets
4. Store the ranked result in the feed cache
5. Return the top 20 tweets to the user

### Ranking Algorithm

Twitter's ranking is ML-based, but the foundational scoring concept (similar to Facebook's EdgeRank) is:

```
Score = Affinity × Weight × Decay

- Affinity: How closely user A interacts with the tweet author (likes, comments, views)
- Weight: Type of interaction (reply > like > retweet > view)
- Decay: How old is the tweet (recent tweets score higher)
```

### Fan-Out Approaches

**Fan-out on Write (Push Model)**

When a user posts a tweet, immediately push it into the home feed of every follower.

![Newsfeed Push Model](/images/newsfeed-push-model.png)

- **Pros:** Feed reads are instant — pre-computed and cached
- **Cons:** Writing to 10 million follower feeds for a celebrity creates enormous write amplification

**Fan-out on Read (Pull Model)**

When a user requests their feed, dynamically aggregate tweets from all followed users at read time.

![Newsfeed Pull Model](/images/newsfeed-pull-model.png)

- **Pros:** No write amplification — tweets are fetched on demand
- **Cons:** High read latency — must query data from potentially thousands of sources and rank results in real time

**Hybrid Model (Twitter's actual approach)**

- For **normal users** (< 10K followers): Fan-out on write — push new tweets to followers' feed caches
- For **celebrities** (> 10K followers, e.g., @elonmusk): Fan-out on read — when a user requests their feed, the celebrity's recent tweets are fetched and merged with the pre-computed portion

This hybrid approach avoids the write amplification of pushing to millions of feeds while keeping feed latency low for the vast majority of users.

---

## Newsfeed Storage

Pre-generated feeds are stored in **Redis** as sorted sets:

```
Key: feed:{userID}
Members: tweetIDs sorted by score (timestamp or ML ranking score)
```

The feed is lazily populated on first access and maintained via fan-out events. Maximum 800 tweets per user feed in cache (Twitter's actual limit was ~800).

---

## Search Architecture

Traditional SQL databases are inadequate for full-text tweet search across billions of documents. **Elasticsearch** is the right tool:

- **Inverted index** allows fast full-text search across all tweet content
- **Sharded and replicated** for fault tolerance and horizontal scaling
- **Near-real-time indexing** — new tweets appear in search results within seconds of posting

### Trending Topics

Trending topics are derived from search volume:

1. Collect all search queries and hashtags in the last N minutes (via Kafka streams)
2. Aggregate and count occurrences in a time-bucketed sliding window
3. Apply geographic filtering (trends are location-specific)
4. Apply a ranking/filtering model to remove spam
5. Cache the top trending topics in Redis, refreshed every M minutes

---

## Retweets

Retweets are stored as tweets with a `retweet_of` reference:

| id | userID | type | content | retweet_of |
|---|---|---|---|---|
| abc-123 | user-1 | text | "Just shipped our new feature!" | null |
| xyz-789 | user-2 | retweet | null | abc-123 |

This approach allows retweets to appear in follower feeds like regular tweets while maintaining the reference to the original.

---

## Media Architecture

Tweets with images or videos:

1. Client uploads media to **Media Service** directly (presigned S3 URL pattern)
2. Media Service stores raw file in **Amazon S3**
3. A processing pipeline transcodes videos (FFmpeg), generates thumbnails
4. Processed media is distributed via **CloudFront CDN**
5. Tweet stores `media_url` pointing to CDN endpoint

---

## Notifications

Twitter uses a **push notification pipeline**:

1. An interaction event (mention, like, follow, retweet) is published to **Kafka**
2. **Notification Service** consumes the event
3. Checks user notification preferences and rate limits (no notification spam)
4. Routes to **FCM** (Android) or **APNs** (iOS) based on registered device token

---

## Detailed Design

### Data Partitioning

**Tweets table:** Shard by `tweet_id` (hash-based) or by `user_id` to keep a user's tweets co-located. Hash-based is preferred for even distribution.

**Followers table:** Shard by `follower_id` for efficient "get all followees of user X" queries.

**Feed cache:** Distributed Redis cluster; each user's feed key is stored on a consistent-hash-determined node.

### Caching Strategy

- **Tweet cache:** Cache top 20% most accessed tweets (LRU in Redis)
- **User profile cache:** Cache user profile data (changes rarely; high read frequency)
- **Feed cache:** Pre-generated sorted set of tweet IDs per user

### Mutual Friends / Suggestions

For "People you may know" features, build a social graph (Neo4j or ArangoDB) and perform graph traversal to find users who are followed by multiple people that user A also follows (friend-of-friend relationships).

### Analytics

Kafka → Apache Spark streaming → Aggregated metrics stored in InfluxDB or Druid for time-series dashboards. Event data enables A/B testing, user cohort analysis, and content moderation signal generation.

---

## Advanced Architecture

![Twitter Advanced Design](/images/twitter-advanced-design.png)

### Bottleneck Resolutions

| Bottleneck | Solution |
|---|---|
| Feed generation latency | Pre-compute feeds asynchronously; cache in Redis |
| Celebrity fan-out write amplification | Hybrid model: fan-out on read for high-follower accounts |
| Search over billions of tweets | Elasticsearch cluster with sharding + replication |
| Media storage | S3 + CloudFront CDN |
| Real-time trending | Kafka streaming + sliding window aggregation |
| Single points of failure | Multi-AZ deployment; load balancers at every tier |

---

## Summary

| Component | Technology |
|---|---|
| Newsfeed storage | Redis sorted sets |
| Tweet storage | Apache Cassandra (write-optimized) |
| Search | Elasticsearch |
| Media | Amazon S3 + CloudFront |
| Fan-out pipeline | Apache Kafka + custom fan-out workers |
| Notifications | FCM + APNs via Kafka |
| Social graph | Neo4j or in-memory adjacency lists |
| Analytics | Apache Kafka + Apache Spark |
| Service mesh | Istio + Envoy |
