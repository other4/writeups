---
title: "System Design Case Study — Uber (Ride-Hailing at Global Scale)"
description: "A complete system design for building Uber: real-time location tracking, geospatial driver matching with Quadtrees, surge pricing, ride dispatch, payment processing, and handling 100M daily active users."
author: ["name": "Rajendra Pancholi", "email": "rpancholi522@gmail.com"]
created: "2026-04-18"
updated: "2026-04-18"
thumbnail: "/images/uber-system-design.png"
tags: [system-design, uber, geospatial, quadtree, websockets, case-study, location-tracking]
keywords: ["Uber system design", "Ride hailing architecture", "Geospatial indexing system design", "Quadtree geohashing", "Real-time location tracking", "System design interview Uber"]
---

# System Design Case Study — Uber (Ride-Hailing at Global Scale)

Uber processes over 10 million trips per day, matching riders with nearby drivers in seconds, tracking live locations, managing surge pricing, and handling payments — all in real time. This is one of the most technically challenging system designs because it combines real-time geospatial processing, bidirectional communication, and strict consistency requirements around trip state.

![Uber System Design](/images/uber-system-design.png)

---

## Requirements

### Functional Requirements

**For Customers:**
- View all available cabs in the vicinity with ETA and pricing
- Book a ride specifying source, destination, and cab type
- Track the driver's live location during pickup and trip
- Cancel a ride before pickup
- Rate the trip and driver after completion

**For Drivers:**
- Accept or deny incoming ride requests
- See the customer's pickup location after accepting
- Mark the trip as started and completed
- View earnings history

### Non-Functional Requirements
- High reliability — rides must never be silently lost
- High availability with minimal latency (< 1 second for driver matching)
- Horizontally scalable to support 100M+ DAU globally
- Strongly consistent trip state (a trip cannot simultaneously be accepted by two drivers)

### Extended Requirements
- Surge pricing based on demand/supply imbalance
- Payment processing via third-party payment gateways
- Fraud detection for payment and account abuse
- Analytics for route optimization and business intelligence

---

## Capacity Estimation

- **100 million DAU**, 1 million active drivers
- 10 million rides/day

```
If each user performs 10 actions (check fares, request, track, etc.):
Total requests: 100M × 10 = 1 billion/day
RPS: 1B / 86,400 ≈ 12,000 requests/second

Location updates (drivers send GPS every 5 seconds):
1M drivers × (86,400 / 5) ≈ 17 billion location updates/day
Location update RPS: ~200,000/second
```

**Storage:**
```
1 billion actions × 400 bytes = ~400 GB/day
10 years: 400 GB × 365 × 10 ≈ 1.4 PB
```

| Metric | Estimate |
|---|---|
| DAU | 100 million |
| Active drivers | 1 million |
| Rides/day | 10 million |
| Request RPS | ~12,000 |
| Location update RPS | ~200,000 |
| Storage/10 years | ~1.4 PB |

---

## Data Model

### `customers` table
| Column | Type |
|---|---|
| `id` | UUID |
| `name` | VARCHAR |
| `email` | VARCHAR |
| `phone` | VARCHAR |
| `default_payment_method_id` | UUID |
| `created_at` | TIMESTAMP |

### `drivers` table
| Column | Type |
|---|---|
| `id` | UUID |
| `name` | VARCHAR |
| `license_number` | VARCHAR |
| `rating` | FLOAT |
| `is_available` | BOOLEAN |
| `current_location` | POINT (lat, lng) |
| `created_at` | TIMESTAMP |

### `cabs` table
| Column | Type |
|---|---|
| `id` | UUID |
| `driver_id` | UUID |
| `registration_number` | VARCHAR |
| `type` | ENUM (UberGo, UberX, UberXL, Black) |
| `capacity` | INT |

### `trips` table
| Column | Type |
|---|---|
| `id` | UUID |
| `customer_id` | UUID |
| `driver_id` | UUID |
| `cab_id` | UUID |
| `source_lat` | FLOAT |
| `source_lng` | FLOAT |
| `destination_lat` | FLOAT |
| `destination_lng` | FLOAT |
| `status` | ENUM (requested, accepted, in_progress, completed, cancelled) |
| `fare` | DECIMAL |
| `started_at` | TIMESTAMP |
| `ended_at` | TIMESTAMP |
| `distance_km` | FLOAT |
| `surge_multiplier` | FLOAT |

### `ratings` table
| Column | Type |
|---|---|
| `id` | UUID |
| `trip_id` | UUID |
| `rater_id` | UUID (customer or driver) |
| `ratee_id` | UUID |
| `rating` | INT (1-5) |
| `feedback` | TEXT |

### `payments` table
| Column | Type |
|---|---|
| `id` | UUID |
| `trip_id` | UUID |
| `amount` | DECIMAL |
| `currency` | VARCHAR |
| `status` | ENUM (pending, completed, failed, refunded) |
| `provider` | ENUM (stripe, paypal, cash) |
| `provider_transaction_id` | VARCHAR |

---

## API Design

```
// Request a ride (customer)
POST /rides
Body: { source: {lat, lng}, destination: {lat, lng}, cabType, paymentMethod }
Response 202: { rideID, estimatedFare, estimatedETA }

// Cancel a ride (customer)
DELETE /rides/{rideID}
Body: { reason? }
Response 200: { success }

// Accept a ride (driver)
POST /rides/{rideID}/accept
Response 200: { customerLocation, customerName, estimatedPickupTime }

// Deny a ride (driver)
POST /rides/{rideID}/deny
Response 200: { success }

// Start a trip (driver)
POST /trips/{tripID}/start
Response 200: { tripID, startedAt }

// End a trip (driver)
POST /trips/{tripID}/end
Response 200: { tripID, fare, endedAt }

// Update driver location (driver, called every 5 seconds)
PUT /drivers/{driverID}/location
Body: { lat, lng, heading, speed }
Response 200: { success }

// Rate a trip
POST /trips/{tripID}/rating
Body: { rating: 1-5, feedback? }
Response 201: { success }
```

---

## Architecture

### Core Services

| Service | Responsibility |
|---|---|
| **Customer Service** | Customer authentication, profiles |
| **Driver Service** | Driver authentication, profiles, availability |
| **Ride Service** | Ride matching, nearby driver discovery, ETA calculation |
| **Trip Service** | Trip lifecycle management (start, end, state machine) |
| **Location Service** | Real-time driver location ingestion and geospatial indexing |
| **Payment Service** | Payment processing, fare calculation, refunds |
| **Notification Service** | Push notifications (ride requests, confirmations, alerts) |
| **Analytics Service** | Surge pricing signals, business intelligence |

---

## The Core Problem: Real-Time Driver Matching

When a customer requests a ride, the system must **find the nearest available drivers** within seconds. This is a geospatial query over 1 million+ live driver locations that changes every 5 seconds.

### Approach 1: SQL Geospatial Queries

```sql
SELECT * FROM drivers
WHERE is_available = TRUE
  AND ST_DWithin(
    current_location,
    ST_Point(-122.4016, 37.7564)::geography,
    5000  -- within 5km radius in meters
  )
ORDER BY ST_Distance(current_location, ST_Point(-122.4016, 37.7564)::geography)
LIMIT 10;
```

PostgreSQL with PostGIS extension supports this. Works at small scale but becomes slow at millions of rows with frequent updates.

### Approach 2: Geohashing

Each driver's GPS coordinates are encoded into a **geohash string** (hierarchical alphanumeric code). Drivers with nearby locations share a common geohash prefix.

```
San Francisco (37.7564, -122.4016) → Geohash: 9q8yy9mf

Nearby drivers share prefix "9q8yy" — simple string prefix search
```

**Implementation:**
- Store `geohash` alongside driver location in Redis
- Index by geohash for fast prefix-based lookups
- Query: find all available drivers where `geohash LIKE '9q8yy%'`

**Limitation:** Geohash cells at boundaries may miss nearby drivers just across the boundary. Solve by also searching 8 neighboring cells.

### Approach 3: Quadtree (Recommended for Scale)

A **Quadtree** recursively divides 2D geographic space into four quadrants. Each leaf node stores a list of drivers within that spatial cell. Cells are subdivided when they exceed a driver density threshold.

![Quadtree](/images/quadtree.png)

**Properties:**
- Dense urban areas have many small cells (high precision)
- Rural areas have large cells (few drivers)
- Finding nearby drivers = walk down the tree to the user's quadrant, collect all drivers in that quadrant and adjacent ones

**In-Memory Quadtree:**
- The entire quadtree fits in memory (millions of driver positions × 100 bytes each = a few GB)
- Updates are fast — move a driver from one leaf node to another when their position changes
- Range queries are O(log N + K) where K is the number of drivers returned

**Redis + Quadtree:** Cache the quadtree in Redis (or build an in-process data structure per Ride Service instance). Driver location updates flow through Kafka to keep the quadtree current.

---

## Real-Time Location Tracking

Drivers and customers both need real-time location updates:

### Driver → Server (Location Updates)

Every 5 seconds, the driver's app sends a location update:
- **WebSocket** (persistent connection, low overhead, bidirectional)
- Alternatively, HTTP POST with short interval (simpler but more overhead)

The Location Service receives the update and:
1. Updates the driver's position in the Quadtree (via Kafka → Location Consumer)
2. Updates the driver's `current_location` in the database
3. If driver is on an active trip: fans out the location to the customer's WebSocket connection

### Server → Customer (Live Tracking)

When a customer is tracking a driver's approach:
- Server pushes location updates to customer's WebSocket connection every 5 seconds
- The Ride Service subscribes to location update events for the specific driver via Kafka
- Customer app renders the driver's live position on the map

```
Driver app → WebSocket → Location Service → Kafka (location-updates topic)
→ Ride Service (subscribed to driver's channel) → Customer WebSocket → Customer app
```

---

## Ride Dispatch Flow

![Uber Working](/images/uber-working.png)

1. **Customer** submits ride request (source, destination, cab type).
2. **Ride Service** finds top 3 nearest available drivers via Quadtree lookup.
3. **Notification Service** sends ride request notification to Driver 1 (best match).
4. **Driver 1** has 15 seconds to accept or deny.
5. If accepted: Trip is created, customer is notified with driver ETA and live location. Driver is marked as unavailable.
6. If denied or timeout: Request is sent to Driver 2, then Driver 3.
7. If no driver accepts after 3 attempts: Customer is notified no driver is available (offer retry or surge price incentive).

### Race Condition Prevention

Multiple customers may request a ride simultaneously, and two Ride Service instances might both select the same driver as the best match.

**Solution: Distributed Locking via Redis**

```
SETNX driver_lock:{driverID} {rideID} EX 30
```

Only the first process to acquire the lock can dispatch to that driver. The lock expires after 30 seconds to prevent deadlock if the dispatcher crashes.

Alternatively, implement **optimistic locking** using a driver status version number — the dispatch only succeeds if the driver's status hasn't changed since it was read.

---

## Surge Pricing

Surge pricing dynamically increases fares when demand exceeds supply in a geographic area.

```
Surge Multiplier = f(demand_rate, supply_rate, historical_patterns)
```

**Implementation:**
1. **Analytics Service** continuously monitors ride request rate and available driver count by geohash cell
2. When `demand / supply > threshold` in a cell: compute surge multiplier (e.g., 1.5x, 2x, 3x)
3. Surge multiplier is published to Redis with a TTL
4. Ride Service reads the multiplier when computing fare estimates
5. Customers see the surge indicator before confirming

Surge pricing also incentivizes drivers to move to high-demand areas (shown on the driver's heatmap).

---

## Payment Processing

Rather than building payment infrastructure from scratch:

1. Integrate with a third-party processor: **Stripe**, **Braintree**, or **PayPal**
2. Customer's payment method is tokenized and stored with the payment processor (never stored raw in Uber's database)
3. After trip completion, Ride Service calculates the final fare (including surge, tolls, etc.)
4. Payment Service charges the stored payment method via the processor's API
5. A **webhook** from the payment processor confirms success/failure
6. Payment record is stored in the `payments` table

**Retry logic:** If payment fails (network timeout, insufficient funds), the Payment Service retries with exponential backoff. Persistent failures result in a debt to the customer's account.

---

## Notifications

```
Ride request → Notification Service → FCM (Android) / APNs (iOS)
```

Notification payload includes:
- Pickup location
- Customer name and rating
- Estimated fare
- Cab type requested
- Time limit to accept (15 seconds)

For time-critical notifications (ride requests to drivers), use **high-priority FCM messages** which bypass Doze mode on Android.

---

## Detailed Design

### Data Partitioning

Geographic sharding is a natural fit:
- Partition by **geographic region** (city or metro area)
- All data for a region (drivers, trips, customers in that region) is co-located
- Cross-region queries are rare

Consistent hashing handles re-balancing when regions are added.

### Caching Strategy

| Data | Cache | Policy |
|---|---|---|
| Driver locations (active) | Redis GEOADD + Sorted Set | Updated every 5s; TTL 60s |
| Active trip state | Redis | LRU; write-through |
| Surge multipliers | Redis | TTL 60s; refreshed by Analytics Service |
| User profiles | Redis | LRU; TTL 1 hour |

### Analytics

Driver GPS data → Kafka → Apache Spark:
- **Route optimization:** Identify high-traffic corridors for routing improvements
- **Demand prediction:** ML models predict demand by area and time of day
- **Driver supply analysis:** Identify supply shortfalls before they occur

---

## Advanced Architecture

![Uber Advanced Design](/images/uber-advanced-design.png)

### Bottleneck Resolutions

| Bottleneck | Solution |
|---|---|
| Driver matching latency | In-memory Quadtree with Redis caching |
| Location update throughput | Kafka pipeline for location ingestion |
| Race conditions on driver dispatch | Redis distributed locking |
| Ride Service single node | Multiple instances; stateless; Zookeeper for coordination |
| Payment failures | Retry queue + DLQ for manual review |
| Notification delivery | Kafka-backed notification pipeline with retries |

---

## Summary

| Component | Technology |
|---|---|
| Location tracking | WebSockets (bidirectional) |
| Geospatial matching | Quadtree in Redis + Geohashing |
| Location event stream | Apache Kafka |
| Primary database | PostgreSQL (trips, users), Cassandra (location history) |
| Cache | Redis (locations, surge, sessions) |
| Payment processing | Stripe / Braintree |
| Notifications | FCM + APNs via Kafka |
| Analytics | Kafka + Apache Spark |
| Service mesh | Istio + Envoy |
| Service discovery | Consul |
