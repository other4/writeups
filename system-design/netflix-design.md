---
title: "System Design Case Study — Netflix (Video Streaming at Global Scale)"
description: "A full system design for a Netflix-like video streaming platform: video upload and processing pipelines, adaptive bitrate streaming, CDN strategy, search, recommendation systems, and handling 200M daily active users."
author: ["name": "Rajendra Pancholi", "email": "rpancholi522@gmail.com"]
created: "2026-04-18"
updated: "2026-04-18"
thumbnail: "/images/netflix-design.png"
tags: [system-design, netflix, video-streaming, cdn, case-study, transcoding]
keywords: ["Netflix system design", "Video streaming architecture", "Adaptive bitrate streaming", "CDN video delivery", "Video transcoding pipeline", "System design interview Netflix"]
---

# System Design Case Study — Netflix (Video Streaming at Global Scale)

Netflix serves 200 million subscribers in 190 countries, streaming over 1 billion hours of video per month. Building a platform at this scale requires solving fundamental challenges in video processing, global content delivery, adaptive streaming, and personalized recommendations.

![Netflix System Design](/images/netflix-design.png)

---

## Requirements

### Functional Requirements
- Users can stream TV shows and movies on any device (web, iOS, Android, Smart TV)
- Content team uploads new videos; platform processes and distributes them
- Users can search content by title, actor, genre, or tag
- Resume playback from the point where the user left off
- Users can leave comments/reviews (like YouTube)

### Non-Functional Requirements
- High availability — streaming must work even during partial infrastructure failures
- High reliability — no uploaded video is ever lost
- Low latency — video must start within 2 seconds on a good connection
- Adaptive quality — video quality adjusts dynamically based on user's bandwidth

### Extended Requirements
- Geographic content restrictions (geo-blocking by licensing agreements)
- Recommendation engine based on viewing history
- Metrics and analytics for content performance

---

## Capacity Estimation

- **200 million DAU**, each watching ~5 videos/day
- **200:1 read/write ratio** (watches far exceed uploads)

```
Watches/day: 200M × 5 = 1 billion/day
Uploads/day: 1 billion / 200 = 5 million/day

Write RPS: 5M / 86,400 ≈ 58 uploads/second
Read RPS: 1B / 86,400 ≈ 12,000 streams/second
```

**Storage (average 100 MB per uploaded video):**
```
5 million × 100 MB = 500 TB/day
10 years: 500 TB × 365 × 10 ≈ 1,825 PB (1.8 EB)
```

**Bandwidth:**
```
500 TB/day ÷ 86,400s ≈ 5.8 GB/second ingress
```

Note: After multi-resolution transcoding, each video is stored in multiple formats (4K, 1080p, 720p, 480p, 360p), multiplying storage by ~5x. This is offset by CDN distribution reducing origin bandwidth.

| Metric | Estimate |
|---|---|
| DAU | 200 million |
| Streams/second | ~12,000 |
| Storage/day | ~500 TB |
| Storage/10 years | ~1,825 PB |
| Bandwidth | ~5.8 GB/s |

---

## Data Model

### `users` table
| Column | Type |
|---|---|
| `id` | UUID |
| `email` | VARCHAR |
| `subscription_plan` | ENUM (basic, standard, premium) |
| `country` | VARCHAR |
| `created_at` | TIMESTAMP |

### `videos` table
| Column | Type |
|---|---|
| `id` | UUID |
| `title` | VARCHAR |
| `description` | TEXT |
| `duration_seconds` | INT |
| `genre` | ENUM |
| `content_rating` | ENUM |
| `available_countries` | JSONB |
| `stream_url_base` | VARCHAR (base path for multi-resolution streams) |
| `created_at` | TIMESTAMP |

### `views` table (watch history and resume position)
| Column | Type |
|---|---|
| `id` | UUID |
| `user_id` | UUID |
| `video_id` | UUID |
| `watch_offset_seconds` | INT (resume position) |
| `watch_percentage` | FLOAT |
| `device_type` | ENUM |
| `country` | VARCHAR |
| `watched_at` | TIMESTAMP |

### `tags` table
| Column | Type |
|---|---|
| `video_id` | UUID |
| `tag` | VARCHAR |

### `comments` table
| Column | Type |
|---|---|
| `id` | UUID |
| `video_id` | UUID |
| `user_id` | UUID |
| `content` | TEXT |
| `created_at` | TIMESTAMP |

---

## API Design

```
// Upload a video (content team)
POST /videos
Body: { title, description, tags[], stream: byte[] }
Response 201: { videoID, processingStatus }

// Stream a video
GET /videos/{videoID}/stream?codec=h264&resolution=1080p&offset=1200
Response: VideoStream (byte stream)

// Search videos
GET /search?q={query}&genre={genre}&page={cursor}
Response: [{ video, matchScore }]

// Get watch history (for resume)
GET /users/{userID}/history
Response: [{ videoID, watchOffsetSeconds, watchPercentage, watchedAt }]

// Add a comment
POST /videos/{videoID}/comments
Body: { content }
Response 201: { commentID }

// Get recommendations
GET /users/{userID}/recommendations?limit=20
Response: [{ video, recommendationScore }]
```

---

## Architecture

### Core Services

| Service | Responsibility |
|---|---|
| **User Service** | Authentication, subscription management |
| **Stream Service** | Video streaming requests, adaptive bitrate delivery |
| **Media Service** | Video upload ingestion, processing pipeline |
| **Search Service** | Full-text search via Elasticsearch |
| **Recommendation Service** | ML-based personalized recommendations |
| **Analytics Service** | View tracking, content performance metrics |

---

## Video Processing Pipeline

Uploading a raw 4K two-hour film can produce 4+ TB of data. Before streaming, this must be processed into multiple formats and resolutions.

![Video Processing Pipeline](/images/video-processing-pipeline.png)

The pipeline is event-driven via a message queue. When a video is uploaded, it enters a processing queue and passes through these stages:

### Stage 1: File Chunking

The raw video is split into **2-10 second chunks** (scenes, not fixed-duration chunks as Netflix uses scene boundaries). Chunking enables:
- Parallel processing of different parts of the video
- Efficient CDN distribution
- Smooth adaptive streaming (client can request specific chunks at different quality levels)

### Stage 2: Content Filter

An ML model screens for:
- **Copyright violations** (Content ID-style fingerprinting)
- **NSFW content** (for age-rating enforcement)
- **Duplicate content** (exact duplicates are rejected)

Videos that fail screening are sent to a **Dead-Letter Queue** for manual moderation review.

### Stage 3: Transcoder

The video is transcoded from its original format (ProRes, RAW, etc.) to distribution formats using codecs optimized for streaming:
- **H.264/AVC** — widest device compatibility
- **H.265/HEVC** — ~50% better compression than H.264 (used for 4K)
- **VP9** — Google's open codec (used by YouTube)
- **AV1** — next-gen open codec, best compression, higher encoding cost

Tools: [FFmpeg](https://ffmpeg.org) (open-source), [AWS Elemental MediaConvert](https://aws.amazon.com/mediaconvert) (managed).

### Stage 4: Multi-Resolution Encoding

Each transcoded video is encoded at multiple resolutions:

| Resolution | Bitrate (H.264) | Bandwidth Requirement |
|---|---|---|
| 4K (2160p) | ~15-25 Mbps | 25+ Mbps |
| 1080p | ~4-8 Mbps | 5+ Mbps |
| 720p | ~2.5-4 Mbps | 3+ Mbps |
| 480p | ~1-2 Mbps | 1.5+ Mbps |
| 360p | ~0.5-1 Mbps | 0.7+ Mbps |

Each resolution variant is chunked and stored in S3. The **HLS manifest file** (`.m3u8`) indexes all available quality levels and chunk URLs.

### Stage 5: Storage

Processed video chunks are uploaded to **Amazon S3** (or equivalent object storage) organized by videoID and quality level:
```
s3://netflix-videos/{videoID}/{resolution}/{chunk_number}.ts
s3://netflix-videos/{videoID}/master.m3u8
```

---

## Adaptive Bitrate Streaming (ABR)

Users have vastly different network conditions — from fiber (100+ Mbps) to mobile data (1-5 Mbps). **Adaptive Bitrate Streaming** dynamically adjusts video quality based on the user's current bandwidth.

**Protocol: HTTP Live Streaming (HLS)**

1. Client requests the **master manifest** (`master.m3u8`) which lists all available quality levels.
2. Client selects an initial quality based on measured bandwidth.
3. Client requests video **chunks** sequentially.
4. The HLS player monitors download speed. If download is slower than playback rate → switch to lower quality. If faster → switch to higher quality.
5. Quality switches happen at chunk boundaries — seamlessly to the viewer.

**Resume Playback:**
When a user resumes a video, the client sends the `offset` parameter (stored in the `views.watch_offset_seconds` field), and the server returns the manifest URL starting from that chunk timestamp.

---

## Content Delivery — Netflix Open Connect

For most services, a third-party CDN (CloudFront, Fastly) is sufficient. Netflix at its scale built its own CDN called **Open Connect**.

**Netflix Open Connect:**
- Netflix deploys **Open Connect Appliances (OCAs)** — dedicated video cache servers — directly inside ISP data centers worldwide (1000+ locations)
- ~95% of Netflix traffic is served directly from OCA appliances, not Netflix's origin servers
- OCAs are filled with popular content during off-peak hours (predictive caching)
- If an OCA is unavailable, traffic falls back to Netflix's own servers

**For a standard system design, use a managed CDN:**

| CDN | Notes |
|---|---|
| [Amazon CloudFront](https://aws.amazon.com/cloudfront) | Tight AWS integration; Lambda@Edge |
| [Cloudflare CDN](https://www.cloudflare.com/cdn) | Global network; DDoS protection |
| [Fastly](https://www.fastly.com) | Real-time purging; used by streaming services |

---

## Search Architecture

Video search across millions of titles requires **Elasticsearch**:

- Index: `title`, `description`, `tags`, `cast`, `director`, `genre`
- Full-text search with relevance scoring
- Faceted filtering: by genre, year, rating, duration
- Geo-filtering: only return content available in the user's country

**Trending Content:**
Cache the most-searched queries in the last N hours. Update rankings every M minutes via a batch job. Apply popularity + freshness weighting.

---

## Recommendation Engine

Netflix's recommendation system is one of the most sophisticated in the world. The foundational algorithm is **Collaborative Filtering**:

```
"Users who watch similar content to you also watched X, so we recommend X."
```

Netflix's actual system tracks:
- Viewing history (titles, completion rates, time of day)
- Search history
- Ratings (explicit and implicit)
- Device type (different viewing patterns on TV vs mobile)
- Profile (user's age, location)
- Row interactions (which rows a user browses vs ignores)

The output is a personalized row ordering AND video ordering within each row.

---

## Geo-Blocking

Content licensing restricts which countries can access specific titles. Implementation:

1. Determine user's location from IP geolocation or profile country setting
2. Check if requested `videoID` is licensed for that country (stored in `videos.available_countries`)
3. If not available: return HTTP 451 (Unavailable for Legal Reasons) and suggest available content
4. CloudFront supports geographic restrictions at the CDN level (block requests from certain countries at the edge)

---

## Advanced Architecture

![Netflix Advanced Design](/images/netflix-advanced-design.png)

### Data Partitioning

- **Videos metadata:** PostgreSQL with read replicas (infrequent writes, many reads)
- **Views/watch history:** Apache Cassandra (time-series, high write throughput, efficient user-based queries)
- **Search index:** Elasticsearch cluster (sharded by video ID)

### Caching Strategy

- **Video metadata cache:** Redis, LRU eviction (title info, thumbnail URLs)
- **Search results cache:** Cache popular queries for 5 minutes
- **Recommendation cache:** Cache recommendations per user, refresh every few hours

### Analytics Pipeline

```
User events (play, pause, skip, search) 
  → Kafka 
  → Apache Spark Streaming (real-time) 
  → InfluxDB / Druid (time-series storage)
  → Grafana dashboards

Batch analytics:
  → S3 data lake 
  → Apache Spark batch 
  → ML model training pipeline
```

---

## Bottleneck Resolution

| Bottleneck | Solution |
|---|---|
| Video upload latency | Multipart upload to S3; chunked ingestion |
| Processing time for large files | Parallel processing pipeline; multiple worker instances |
| Global streaming latency | Open Connect / CDN edge caching |
| Recommendation freshness | Async model retraining pipeline; cache invalidation |
| Search at billions of documents | Elasticsearch cluster with sharding |
| Storage cost | Lifecycle policies; compress older content; tiered storage |

---

## Summary

| Component | Technology |
|---|---|
| Video storage | Amazon S3 (multi-region) |
| Video processing | FFmpeg + AWS Elemental MediaConvert |
| Streaming protocol | HLS (HTTP Live Streaming) |
| CDN | Netflix Open Connect / Amazon CloudFront |
| Metadata DB | PostgreSQL with read replicas |
| Watch history | Apache Cassandra |
| Search | Elasticsearch |
| Recommendations | Collaborative Filtering + ML models |
| Analytics | Kafka + Apache Spark + Druid |
| Caching | Redis (metadata, search, recommendations) |
