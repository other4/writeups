# The IoT Protocol Stack

The IoT protocol stack can be mapped to the seven-layer OSI (Open Systems Interconnection) model, which is widely used to understand and design network architectures. Each layer in the IoT protocol stack has specific roles and protocols that ensure efficient and reliable communication between IoT devices and systems.

---

## 1. Physical Layer
**Function:**  
The physical layer is responsible for the physical connection of devices to the network. It handles the transmission of raw data between devices and physical transmission media, converting digital information into electrical, radio, or optical signals.

**Protocols/Technologies:**
- **Wi-Fi**: A widely used wireless networking technology.  
- **Bluetooth**: Short-range wireless communication.  
- **ZigBee**: Low-power, low-data-rate wireless communication.  
- **LTE**: Long-term evolution for mobile communication.  
- **NB-IoT**: Narrowband IoT for low-power wide-area networks.  
- **LoRaWAN**: Long-range, low-power wireless communication.  

---

## 2. Data Link Layer
**Function:**  
This layer ensures reliable data transfer across the physical link. It handles error detection and correction, flow control, and the establishment and termination of connections between devices.

**Protocols/Technologies:**
- **Ethernet**: A common wired networking technology.  
- **PPP (Point-to-Point Protocol)**: Used for direct communication between two network nodes.  
- **IEEE 802.15.4**: A standard for low-rate wireless personal area networks, used in ZigBee.  

---

## 3. Network Layer
**Function:**  
The network layer is responsible for routing data packets from the source to the destination across multiple networks. It handles logical addressing, traffic directing, and congestion control.

**Protocols/Technologies:**
- **IP (Internet Protocol)**: The primary protocol for routing data across networks.  
- **RPL (Routing Protocol for Low-Power and Lossy Networks)**: Designed for low-power and lossy networks.  
- **6LoWPAN (IPv6 over Low-Power Wireless Personal Area Networks)**: An adaptation layer for IPv6 over IEEE 802.15.4.  

---

## 4. Transport Layer
**Function:**  
This layer ensures end-to-end communication and data transfer reliability. It manages error correction, flow control, and data segmentation and reassembly.

**Protocols/Technologies:**
- **TCP (Transmission Control Protocol)**: Provides reliable, ordered, and error-checked delivery of data.  
- **UDP (User Datagram Protocol)**: Offers a simpler, connectionless communication model with minimal overhead.  

---

## 5. Session Layer
**Function:**  
The session layer manages sessions or connections between applications. It establishes, maintains, and terminates communication sessions.

**Protocols/Technologies:**
- **MQTT (Message Queuing Telemetry Transport)**: A lightweight messaging protocol for small sensors and mobile devices.  
- **CoAP (Constrained Application Protocol)**: Designed for use with constrained nodes and networks.  
- **AMQP (Advanced Message Queuing Protocol)**: Used for transactional messages between servers.  
- **XMPP (Extensible Messaging and Presence Protocol)**: A communication protocol for message-oriented middleware.  

---

## 6. Presentation Layer
**Function:**  
This layer translates data between the application layer and the network. It handles data encryption, compression, and translation.

**Protocols/Technologies:**
- **JSON (JavaScript Object Notation)**: A lightweight data interchange format.  
- **XML (eXtensible Markup Language)**: A markup language for encoding documents.  
- **Data Encryption Standards**: Various standards for securing data.  

---

## 7. Application Layer
**Function:**  
The application layer provides network services directly to end-user applications. It defines protocols for specific data exchange and communication needs.

**Protocols/Technologies:**
- **HTTP (HyperText Transfer Protocol)**: The foundation of data communication for the World Wide Web.  
- **MQTT**: Also used at the application layer for lightweight messaging.  
- **CoAP**: Also used at the application layer for constrained environments.  
- **DDS (Data Distribution Service)**: A middleware protocol for data-centric connectivity.  
- **OPC UA (OPC Unified Architecture)**: A machine-to-machine communication protocol for industrial automation.  


--- 


Perfect question 👍 Let’s carefully connect **segmentation, fragmentation, and framing** across the **OSI layers**, along with **devices** and **protocols**.

---

# 🌐 Data Handling Concepts Across OSI Layers

When data travels from one computer to another, each **layer of the OSI model** prepares or breaks down the data differently.

---

## 1. **Segmentation** (Transport Layer – Layer 4)

* **What:** Splitting big application data (like a video file) into **smaller chunks** called *segments*.
* **Why:** Networks can’t send huge data in one go, so it must be broken down.
* **Who Does It:**

  * **Protocols:** TCP (segments), UDP (datagrams).
  * **Devices:** End systems (PCs, servers, smartphones).
* **Extra Info:** Each segment gets a **port number** (so it knows which app it belongs to).

👉 Example: A 10 MB file is split into 1,000 segments before transmission.

---

## 2. **Fragmentation** (Network Layer – Layer 3)

* **What:** Breaking down **IP packets** into smaller pieces if they are too large for the network’s **MTU (Maximum Transmission Unit)**.
* **Why:** Different networks have different size limits (e.g., Ethernet = 1500 bytes).
* **Who Does It:**

  * **Protocols:** IPv4 allows fragmentation, IPv6 mostly avoids it (done at the source).
  * **Devices:** Routers can fragment packets.
* **Extra Info:** Each fragment gets reassembled at the destination using fragment offsets.

👉 Example: If a packet is 4000 bytes and the network allows only 1500, the router fragments it into 3 smaller packets.

---

## 3. **Framing** (Data Link Layer – Layer 2)

* **What:** Encapsulating packets into **frames** with headers and trailers.
* **Why:** To provide error detection (using CRC), addressing (MAC addresses), and synchronization.
* **Who Does It:**

  * **Protocols:** Ethernet, PPP, Wi-Fi (IEEE 802.11), HDLC.
  * **Devices:** Switches and NICs (Network Interface Cards).
* **Extra Info:** Each frame has **source/destination MAC address** and an error check (CRC).

👉 Example: A 1500-byte IP packet is put inside an Ethernet frame with 14-byte header + 4-byte trailer.

---

# ✅ Putting It All Together (with OSI Layers)

| OSI Layer          | Function                                           | Concept           | Protocols            | Devices                  |
| ------------------ | -------------------------------------------------- | ----------------- | -------------------- | ------------------------ |
| **Transport (L4)** | Breaks big data into smaller units for reliability | **Segmentation**  | TCP, UDP             | End devices (PC, server) |
| **Network (L3)**   | Adapts packet size to network MTU                  | **Fragmentation** | IPv4, IPv6           | Routers                  |
| **Data Link (L2)** | Adds headers/trailers for local delivery           | **Framing**       | Ethernet, Wi-Fi, PPP | Switches, NICs           |

---

# 🚦 Simple Real-World Analogy

* **Segmentation (L4):** A book is split into chapters → easier to handle.
* **Fragmentation (L3):** A big chapter is too large for your small bag → cut into smaller bundles.
* **Framing (L2):** Each bundle is put in an envelope with sender/receiver address and sealed.

---

Perfect 👍 Let’s take your example: you want to send the word **“hellow”** over a network.

---

## Step by Step Journey of `"hellow"`

### 🔹 1. **Segmentation (Transport Layer – L4)**

* Suppose `"hellow"` is **too big** (imagine sending a book, not just one word).
* The transport layer (TCP/UDP) **cuts it into smaller pieces**.
* Example: `"hel"` + `"low"`

👉 Now we have **segments**:

```
Segment 1: "hel"
Segment 2: "low"
```

---

### 🔹 2. **Fragmentation (Network Layer – L3)**

* Each segment is put inside an **IP packet**.
* If the packet is **too large for the network**, the router cuts it further.
* Example: `"hel"` might be too large → split into `"he"` + `"l"`

👉 Now we have **fragments**:

```
Packet 1: "he"
Packet 2: "l"
Packet 3: "low"
```

---

### 🔹 3. **Framing (Data Link Layer – L2)**

* Each fragment is now **packed in a frame** with:

  * **Sender MAC address**
  * **Receiver MAC address**
  * **Error check**
* Example:

```
Frame 1: [Src: PC1 | Dest: Router | Data: "he"]
Frame 2: [Src: PC1 | Dest: Router | Data: "l"]
Frame 3: [Src: PC1 | Dest: Router | Data: "low"]
```

---

### 🔹 4. **Transmission (Physical Layer – L1)**

* Frames are converted into **electrical signals / radio waves**.
* Sent over **cables or Wi-Fi** to the destination.

---

### 🔹 5. **At the Receiver Side**

* Frames are **opened** → fragments extracted.
* Fragments are **reassembled** into the original segments.
* Segments are **combined** back into the message.

👉 Finally, the receiver gets:

```
"hellow"
```

---

## ✅ Quick Analogy

* **Segmentation:** Cutting “hellow” into `"hel"` + `"low"` like pizza slices.
* **Fragmentation:** Router says slice `"hel"` is too big, so it cuts again into `"he"` + `"l"`.
* **Framing:** Each piece is put in an envelope with **To/From address**.
* **At destination:** All pieces are unpacked and joined → `"hellow"`.

---

Great — let’s walk the **whole detailed process** for sending a *large data set* from one host to another, layer-by-layer, showing exactly what each layer does at the **sender** and the **receiver**. I’ll use a concrete example so it’s easier to follow:

**Example:** send a **5 MB** file from **Host A** → **Host B** over a typical Ethernet-based path (MTU 1500 bytes).
(5 MB = 5 × 1024 × 1024 = **5,242,880 bytes**)

---

# 1) Quick overview (end-to-end)

When you send a large file the system breaks it into pieces, packages each piece with the right headers at each layer, sends those packages across the network, and the receiver removes headers and reassembles the pieces back to the original file. The main per-layer tasks are:

* **Application/Presentation/Session** — prepare data, encode, encrypt, open/maintain session.
* **Transport (L4)** — **segmentation**, sequence numbers, retransmit & flow-control (TCP) or datagrams (UDP).
* **Network (L3)** — encapsulate into IP packets, routing, fragmentation (IPv4 routers or source for IPv6), TTL.
* **Data Link (L2)** — frame each packet (MAC addresses, FCS), obey local MTU.
* **Physical (L1)** — convert frames to bits/signals and put on the medium.

---

# 2) Concrete numbers for our example

* Typical Ethernet MTU = **1500 bytes**.
* TCP header (typical) = **20 bytes**, IP header = **20 bytes** → payload per IP packet (MSS) ≈ **1500 − 20 − 20 = 1460 bytes**.
* File size = **5,242,880 bytes** → number of TCP segments ≈ **5,242,880 ÷ 1460 = 3,591 full segments** + **20 bytes** remainder → total **3,592 TCP segments**.
  So the transport layer will deliver \~3,592 segments (each will become a packet/frame on the wire).

---

# 3) Sender side — step-by-step by OSI layer

### Application Layer (L7)

**What happens:**

* Application (e.g., a file transfer program, HTTP, SFTP) reads the file and hands bytes to lower layers.
  **Example actions:**
* Break file into request bodies, or stream it into the socket API.
  **Devices/Protocols:** App process, HTTP/S, FTP, whatever you used.

---

### Presentation & Session (L6 & L5)

**What happens:**

* Optional: data compression, character encoding, and encryption (TLS) occur here.
* Session layer establishes/maintains the “conversation” (e.g., TLS handshake establishes secure session).
  **Important note:** If TLS is used, the transport layer will segment the **encrypted bytes**, not the original plaintext; TLS also has its own record layer with its own fragmentation rules.

---

### Transport Layer (L4) — **Segmentation, reliability, flow control**

**What happens:**

1. **Connection setup (TCP)**: 3-way handshake (SYN → SYN/ACK → ACK). During handshake the peers advertise options (MSS, window scaling, SACK permitted, timestamps).
2. **Segmentation:** Transport breaks the application data into segments sized by the negotiated MSS (≈1460 bytes payload).
3. **Sequencing:** Each segment gets a **sequence number** so the receiver can reorder and detect missing data.
4. **Flow control:** Sender must respect the receiver’s advertised window (how much the receiver can buffer).
5. **Congestion control:** Sender controls transmit rate using algorithms (slow start, congestion avoidance, fast retransmit/recovery). If packet loss occurs, cwnd decreases and sender slows down.
6. **Reliability:** Receiver sends ACKs (cumulative or selective). Sender retransmits on timeout or by fast-retransmit (duplicate ACKs).
   **Headers/fields added:** Source port, destination port, sequence number, ACK number, flags (SYN/ACK/FIN), window size, checksum.
   **Device/Protocol:** Host’s TCP stack.

---

### Network Layer (L3) — **Encapsulation & routing**

**What happens:**

1. TCP segment becomes the **payload** of an IP packet. IP header is added (source IP, destination IP, protocol field = TCP).
2. **TTL** is set; **IP ID** and fragmentation flags may be set.
3. **Routing:** Routers examine the destination IP and forward the packet hop-by-hop toward Host B.
4. **Fragmentation**:

   * **IPv4:** routers *can* fragment if the next link MTU is smaller (unless DF/Don't Fragment set). Fragmented packets have fragment offsets and MF (more fragments) flags. Reassembly happens at the destination.
   * **IPv6:** routers **do not** fragment; instead they send an ICMPv6 “Packet Too Big” back to the source so the source can do Path MTU Discovery and send smaller packets (or source can fragment via Fragment extension header).
     **Headers/fields added:** IP header (src/dst IP, protocol, TTL), possibly fragment offset and flags.
     **Devices:** Routers do forwarding; Host A’s IP stack creates packets.

---

### Data Link Layer (L2) — **Framing & local delivery**

**What happens:**

1. Each IP packet is put inside a **frame** suitable for the physical network (e.g., Ethernet frame).
2. Frame fields: **Destination MAC**, **Source MAC**, **Ethertype**, **payload = IP packet**, **Frame Check Sequence (FCS)** (CRC).
3. If frame payload is larger than link MTU, the packet must be split or PMTUD used — typically L2 enforces an MTU (Ethernet 1500 bytes).
4. On switched LANs, **ARP** (Address Resolution Protocol) is used to map the destination IP to a destination MAC if needed.
5. Link-layer may perform its own error detection and in some technologies (Wi-Fi) local retransmissions/ACKs at L2.
   **Devices:** NIC (Network Interface Card), switch.

---

### Physical Layer (L1)

**What happens:**

* The NIC converts the frame to electrical/optical/radio signals and sends bits across the medium (copper, fiber, Wi-Fi).
* Encoding, modulation, line signalling are handled here.

---

# 4) What happens on the wire (transmission)

* Frames travel across physical media through switches and routers.
* If packets are lost (collision, interference, congested router queue), the receiver will not ACK some sequence numbers and the sender will retransmit after timeout or via fast retransmit.

---

# 5) Receiver side — reverse the process

### Physical Layer (L1)

* NIC receives signals and reconstructs frames (bits → bytes).

### Data Link Layer (L2)

* Check FCS; if frame corrupted it may be dropped (and, e.g., Wi-Fi may request retransmission at L2).
* Remove frame header/trailer, pass IP packet up.

### Network Layer (L3)

* Inspect IP header (check checksum for IPv4), decrement TTL and drop if TTL expired.
* If packet is a fragment (IPv4), receiver buffers fragments and reassembles them using IP ID and fragment offset. If a fragment is lost, the entire original IP datagram cannot be reassembled until missing fragments arrive (reassembly only at destination).
* Pass reassembled IP packet with its transport payload to Transport layer.

### Transport Layer (L4)

* Check transport checksum (e.g., TCP checksum).
* **Reordering & reassembly:** Place segments into a receive buffer according to sequence numbers. If some segments are missing, the data is not delivered to the application until in-order bytes up to the next missing byte are available (unless app uses out-of-order APIs).
* **ACKing:** Receiver sends ACKs back to the sender advertising the next expected sequence number and available window. If SACK is used the receiver can inform which blocks were received so sender retransmits only missing parts.
* **Flow control:** Receiver tells sender how much buffer space it has (window).
* When contiguous in-order data arrives, it is delivered to the application.

### Session/Presentation/Application (L5-L7)

* If TLS was used, TLS record layer decrypts and verifies authenticity and integrity, reassembles any TLS records and passes plaintext to the application.
* Application receives the original bytes and writes them to file.

---

# 6) Special concerns for *large* transfers

### Buffering & memory

* Receiver needs enough buffer to hold out-of-order segments. If receiver buffer is small it advertises a small window → sender slows down.

### Retransmissions & timeouts

* Lost packets cause retransmission which adds delay. TCP uses RTT measurements to set retransmission timeout (RTO). Retransmissions can dramatically affect throughput on high-latency paths.

### Congestion control

* TCP reduces sending rate on packet loss (interpreted as congestion). On long transfers, congestion control behavior (slow start, AIMD) determines how fast the sender ramps up and what steady throughput is reached.

### Path MTU Discovery (PMTUD)

* To avoid fragmentation and improve efficiency, the sender can discover the smallest MTU along the path and send only packets that fit. If intermediate routers drop packets and return ICMP “fragmentation needed”, sender reduces packet size.

### Reassembly timeouts (IPv4)

* If not all fragments arrive within a timeout, the fragments are discarded and the whole datagram is lost (requiring higher-layer retransmission).

### Encryption (TLS)

* If TLS is used, the transport layer sees encrypted blobs. TLS has its own record boundaries and can add overhead (handshake, padding).

---

# 7) Encapsulation example (one segment) — ASCII view

Sender builds:

```
Application data:    [ chunk #123 (1460 bytes) ]
Transport (TCP):     [ TCP header | seq=..., srcport, dstport | payload=chunk ]
Network (IP):        [ IP header(srcIP,dstIP) | payload = TCP segment ]
Data Link (Ethernet):[ Eth header(srcMAC,dstMAC) | payload = IP packet | FCS ]
Physical:            bits on wire
```

Receiver reverses:

```
Physical -> Ethernet -> IP -> TCP -> Application
```

---

# 8) Devices involved

* **End hosts (PC, server, phone):** do Application, Presentation, Session, Transport, Network encapsulation and final reassembly.
* **Switches:** operate at L2 (forward frames by MAC).
* **Routers:** operate at L3 (forward packets by IP; may fragment in IPv4).
* **Firewalls / NAT:** may inspect/modify L3/L4 fields (affects port, IP), sometimes payload (proxying).
* **NICs & Drivers:** handle framing and physical signaling.

---

# 9) Short example timeline (5 MB transfer)

1. App opens socket, TLS handshake completes (if any).
2. TCP handshake completes; MSS determined (≈1460 bytes).
3. Sender segments file into \~3,592 segments.
4. Sender starts sending segments according to cwnd and receiver window.
5. Router forwards packets; if MTU smaller than expected, ICMP “fragmentation needed” may reach source → source resends smaller segments.
6. Receiver ACKs received bytes; sender slides window and sends next bytes.
7. Some segments lost → sender retransmits.
8. After all bytes are acknowledged, TCP connection is closed (FIN/ACK handshake).
9. Application writes file to disk.

---

# 10) Key takeaways (simple & practical)

* **Segmentation** = transport breaks big data into segments and numbers them (sender & receiver track sequence numbers).
* **Fragmentation** = IP layer splits packets if a link’s MTU is too small (IPv4 routers can fragment; IPv6 expects source to do PMTUD).
* **Framing** = data-link puts IP packets into frames with MAC addresses and error checks (switches forward frames).
* **Reliability** (TCP) — sequence numbers, ACKs, retransmit, flow & congestion control.
* **Performance matters:** MSS/MTU, RTT, packet loss, receiver window and congestion control determine how fast a large transfer completes.

---

# 🔹 Steps to Calculate TCP Sequence Numbers

### 1. **Start with the Initial Sequence Number (ISN)**

* In your question, the ISN = **10,001**.
* This is the sequence number of the **first byte** in the first segment.

---

### 2. **Know the Segment Size**

* Each segment carries a certain number of bytes.
* In your case, each segment = **1,000 bytes**.

---

### 3. **Add Segment Size to Get Next Sequence Number**

* The sequence number of the **next segment** is:

$$
\text{Next Seq Num} = \text{Current Seq Num} + \text{Number of Bytes in Current Segment}
$$

---

### 4. **Repeat for All Segments**

Keep adding the **payload size** until you cover the entire data.

---

# 🔹 Example: File = 5,000 bytes, ISN = 10,001, Segment size = 1,000

* **Segment 1:**
  Seq = 10,001 (covers bytes 10,001 → 11,000)

* **Segment 2:**
  Seq = 10,001 + 1,000 = 11,001 (covers 11,001 → 12,000)

* **Segment 3:**
  Seq = 11,001 + 1,000 = 12,001 (covers 12,001 → 13,000)

* **Segment 4:**
  Seq = 12,001 + 1,000 = 13,001 (covers 13,001 → 14,000)

* **Segment 5:**
  Seq = 13,001 + 1,000 = 14,001 (covers 14,001 → 15,000)

---

# ✅ General Formula

If **ISN = N** and each segment has **L bytes**, then the sequence numbers are:

$$
\text{Segment i Seq Num} = N + (i-1) \times L
$$

For your example:

$$
Seq(i) = 10001 + (i-1) \times 1000
$$

So: 10001, 11001, 12001, 13001, 14001 ✔️

---

# 🔹 Refresher on Sequence & ACK Numbers

* **Sequence number (SEQ):** Byte number of the **first byte** in the current segment.
* **Acknowledgment number (ACK):** Next byte number the receiver **expects** from the sender.

  * In other words, ACK = SEQ of current segment + segment size.
  * Receiver sends this back to say: *“I got everything up to this byte, send me the next one.”*

---

# 🔹 Example: 5,000 Bytes, ISN = 10,001, 5 Segments of 1,000 Bytes

### 📌 Segment 1

* **Sender SEQ = 10,001**
* Covers bytes: 10,001 → 11,000
* **Receiver ACK = 11,001** (next expected byte)

---

### 📌 Segment 2

* **Sender SEQ = 11,001**
* Covers bytes: 11,001 → 12,000
* **Receiver ACK = 12,001**

---

### 📌 Segment 3

* **Sender SEQ = 12,001**
* Covers bytes: 12,001 → 13,000
* **Receiver ACK = 13,001**

---

### 📌 Segment 4

* **Sender SEQ = 13,001**
* Covers bytes: 13,001 → 14,000
* **Receiver ACK = 14,001**

---

### 📌 Segment 5

* **Sender SEQ = 14,001**
* Covers bytes: 14,001 → 15,000
* **Receiver ACK = 15,001**

---

# ✅ Final Table

| Segment | Sender SEQ | Bytes Carried   | Receiver ACK |
| ------- | ---------- | --------------- | ------------ |
| 1       | 10,001     | 10,001 – 11,000 | 11,001       |
| 2       | 11,001     | 11,001 – 12,000 | 12,001       |
| 3       | 12,001     | 12,001 – 13,000 | 13,001       |
| 4       | 13,001     | 13,001 – 14,000 | 14,001       |
| 5       | 14,001     | 14,001 – 15,000 | 15,001       |

---

📌 So the **ACK number is always "next byte expected"**, which = **last byte received + 1**.

