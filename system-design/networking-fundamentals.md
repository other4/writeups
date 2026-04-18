---
title: "IP Addresses, OSI Model, TCP and UDP — Networking Fundamentals for System Design"
description: "A deep dive into the networking fundamentals every system designer must know: IP addresses (IPv4/IPv6), the OSI model layers, and the differences between TCP and UDP."
author: ["name": "Rajendra Pancholi", "email": "rpancholi522@gmail.com"]
created: "2026-04-18"
updated: "2026-04-18"
thumbnail: "/images/networking-fundamentals.png"
tags: [networking, ip-address, osi-model, tcp, udp, system-design]
keywords: ["IP address explained", "OSI model layers", "TCP vs UDP", "Networking fundamentals system design", "IPv4 vs IPv6"]
---

# IP Addresses, OSI Model, TCP and UDP — Networking Fundamentals for System Design

Before designing any distributed system, you need a solid mental model of how data physically travels across a network. This post covers the three core networking concepts every system designer must know: IP addressing, the OSI model, and the TCP/UDP protocol distinction.

![Networking Fundamentals](/images/networking-fundamentals.png)

---

## IP Addresses

An IP (Internet Protocol) address is a **unique identifier assigned to every device on a network**. It enables machines to locate and communicate with each other across the internet or within a local network.

### IPv4

The original Internet Protocol uses a **32-bit numeric dot-decimal notation**, supporting approximately 4.3 billion unique addresses.

```
Example: 102.22.192.181
```

With the explosive growth of internet-connected devices, IPv4 addresses were exhausted, necessitating a new standard.

### IPv6

Introduced in 1998 and deployed through the 2000s, IPv6 uses a **128-bit alphanumeric hexadecimal notation**, providing approximately 3.4 × 10³⁸ unique addresses — effectively unlimited for foreseeable future demand.

```
Example: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
```

### Types of IP Addresses

| Type | Description | Example |
|---|---|---|
| **Public** | Single address representing an entire network externally | IP assigned to your router by the ISP |
| **Private** | Unique address within a local network | 192.168.1.x assigned by home router |
| **Static** | Manually assigned, does not change | Used for servers, VPNs, geo-location services |
| **Dynamic** | Automatically assigned by DHCP, changes over time | Common for consumer devices |

**System Design Implication:** When designing services that require stable endpoints (databases, APIs, load balancers), static IPs or DNS-based service discovery is essential. Dynamic IPs require additional abstraction layers.

---

## The OSI Model

The Open Systems Interconnection (OSI) model is a **conceptual framework that standardizes how network communication is structured** across seven abstraction layers. While real-world networks use TCP/IP (which collapses some layers), the OSI model remains the universal reference for understanding network behavior.

![OSI Model Layers](/images/osi-model.png)

### Layer 7 — Application
The only layer that **directly interacts with user data**. It handles protocols that software applications rely on, not the applications themselves.

- Protocols: HTTP, HTTPS, SMTP, FTP, DNS, WebSocket
- System design relevance: API gateway, load balancers operating at L7, content-based routing

### Layer 6 — Presentation
Handles **data translation, encryption/decryption, and compression**. Ensures that data from the application layer is in a format that the receiving system can understand.

- Responsible for: TLS/SSL encryption, data serialization (JSON, XML, Protobuf)

### Layer 5 — Session
Manages **opening, maintaining, and closing communication sessions** between devices. Synchronizes data transfer using checkpoints.

- Relevant to: WebSocket sessions, RPC sessions

### Layer 4 — Transport
Provides **end-to-end communication** between processes, including segmentation, flow control, and error correction.

- Protocols: TCP (reliable), UDP (unreliable but fast)
- System design relevance: Load balancers operating at L4 use IP/port for routing without inspecting packet content

### Layer 3 — Network
Responsible for **routing packets** between different networks using logical addressing (IP).

- Protocols: IP, ICMP, routing protocols (BGP, OSPF)
- Devices: Routers

### Layer 2 — Data Link
Handles **data transfer between devices on the same network** using physical addressing (MAC addresses).

- Protocols: Ethernet, Wi-Fi (802.11)
- Devices: Switches, network bridges

### Layer 1 — Physical
The actual **physical transmission medium** — cables, fiber optics, radio waves. Converts digital data to physical signals (bits to electrical/optical/radio signals).

### OSI Model Summary Table

| Layer | Name | Protocols/Examples | System Design Role |
|---|---|---|---|
| 7 | Application | HTTP, DNS, SMTP | API routing, content inspection |
| 6 | Presentation | TLS, JSON, XML | Encryption, serialization |
| 5 | Session | WebSocket, RPC | Session management |
| 4 | Transport | TCP, UDP | L4 load balancing, port routing |
| 3 | Network | IP, ICMP | Packet routing |
| 2 | Data Link | Ethernet, Wi-Fi | Same-network delivery |
| 1 | Physical | Cables, fiber | Raw transmission |

---

## TCP vs UDP

At Layer 4, you must choose between two fundamentally different transport protocols: **TCP** (reliability-first) and **UDP** (speed-first).

### TCP — Transmission Control Protocol

TCP is a **connection-oriented protocol** that establishes a connection before any data is transmitted (via a three-way handshake: SYN → SYN-ACK → ACK). It guarantees:

- **Ordered delivery** — packets arrive in the sequence they were sent
- **Error checking** — corrupted packets are detected and retransmitted
- **Flow control** — prevents overwhelming the receiver
- **Congestion control** — adapts to network conditions

**Cost:** Higher overhead due to handshaking, acknowledgments, and retransmission mechanisms.

**Use cases:** HTTP/HTTPS, email (SMTP), file transfer (FTP), database connections — anywhere data integrity is critical.

### UDP — User Datagram Protocol

UDP is a **connectionless protocol** that sends packets (datagrams) without establishing a connection first. It provides:

- **No guaranteed delivery** — packets may be lost
- **No ordering** — packets may arrive out of sequence
- **No congestion control** — sends at maximum rate regardless of network state
- **Minimal overhead** — no handshaking or acknowledgment

**Benefit:** Dramatically lower latency and higher throughput.

**Use cases:** Video streaming, live gaming, DNS queries, VoIP, IoT telemetry — anywhere low latency matters more than perfect delivery.

### TCP vs UDP Comparison

| Feature | TCP | UDP |
|---|---|---|
| Connection type | Connection-oriented | Connectionless |
| Delivery guarantee | Guaranteed | Not guaranteed |
| Ordering | In-order delivery | No ordering |
| Retransmission | Yes, on packet loss | No |
| Speed | Slower | Faster |
| Overhead | High | Low |
| Broadcasting | Not supported | Supported |
| Use cases | HTTPS, SSH, FTP, databases | Streaming, DNS, VoIP, gaming |

### System Design Decision: TCP vs UDP

When designing a system, choose based on these principles:

- **Choose TCP** when data correctness is non-negotiable: financial transactions, user authentication, file transfers, API calls.
- **Choose UDP** when latency matters more than completeness: real-time video/audio, live scoreboards, location tracking with frequent updates (old data is worthless anyway).
- **Hybrid approach:** Some protocols like QUIC (used by HTTP/3) build reliability features on top of UDP to get the best of both worlds.

---

## Putting It All Together

In a typical web request:

1. **DNS** (Layer 7, UDP) resolves the domain to an IP address
2. **TCP handshake** (Layer 4) establishes connection to the server's IP
3. **TLS negotiation** (Layer 6) encrypts the session
4. **HTTP request** (Layer 7) is sent over the encrypted TCP connection
5. **IP routing** (Layer 3) delivers packets across networks
6. **Ethernet frames** (Layer 2) deliver packets within each network segment

Understanding which layer a component operates at directly informs how you design load balancers, proxies, firewalls, and monitoring systems.
