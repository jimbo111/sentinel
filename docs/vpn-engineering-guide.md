# Ring VPN Engineering Guide

> Reference document for engineers working on Ring's on-device VPN. Covers architecture, DNS forwarding, known issues, and future development paths.

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [DNS Forwarding Deep Dive](#2-dns-forwarding-deep-dive)
3. [NWUDPSession Issues & Mitigations](#3-nwudpsession-issues--mitigations)
4. [Configuration Parameters](#4-configuration-parameters)
5. [Troubleshooting Guide](#5-troubleshooting-guide)
6. [Full VPN Roadmap](#6-full-vpn-roadmap)
7. [NWConnection Migration Guide](#7-nwconnection-migration-guide)
8. [Battery & Performance](#8-battery--performance)
9. [Memory Management](#9-memory-management)
10. [References](#10-references)

---

## 1. Architecture Overview

### Current Model: DNS-Only Tunnel

```
┌──────────────────────────────────────────────────────────────┐
│ iOS Device                                                    │
│                                                               │
│  ┌─────────┐     DNS to 198.18.0.1:53     ┌───────────────┐ │
│  │ Apps     │ ──────────────────────────▶  │ Ring Extension │ │
│  │ (Safari, │                              │                │ │
│  │ YouTube, │ ◀──────────────────────────  │ ┌────────────┐│ │
│  │ etc.)    │     DNS response             │ │Rust Engine ││ │
│  └─────────┘                              │ │• DNS parse  ││ │
│       │                                    │ │• Site map   ││ │
│       │ TCP/HTTPS (direct, bypasses tunnel)│ │• SQLite     ││ │
│       │                                    │ └────────────┘│ │
│       ▼                                    │       │        │ │
│   Internet ◀──────────────────────────────│ NWUDPSession   │ │
│   (no VPN)   DNS forwarding               │ ├─▶ 8.8.8.8   │ │
│                                            │ └─▶ 1.1.1.1   │ │
│                                            └───────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

**Key design decisions:**
- Only DNS traffic enters the tunnel (`includedRoutes = 198.18.0.1/32`)
- TCP/HTTPS traffic goes directly to the internet — zero VPN overhead for data
- Virtual DNS IP `198.18.0.1` from RFC 2544 benchmarking range (never routable)
- `matchDomains = [""]` captures ALL DNS queries regardless of domain

**Why this pattern:**
This is the industry-standard architecture used by AdGuard, DNSCloak, NextDNS, 1Blocker, and Lockdown Privacy. Apple's TN3120 says packet tunnels weren't designed for DNS interception, but `NEDNSProxyProvider` (the "right" API) requires MDM-supervised devices — making it impossible for App Store consumer apps.

### What Ring Can and Cannot See

| Data | Visible? | How |
|------|----------|-----|
| Domain names (DNS queries) | Yes | Extracted from DNS query QNAME |
| DNS query types (A, AAAA, HTTPS, MX) | Yes | Parsed from DNS header |
| DNS response IPs | Yes | Parsed from DNS A/AAAA responses |
| TLS SNI (server name) | **No** | TCP doesn't enter tunnel |
| TLS version | **No** | Requires TCP ClientHello |
| Byte volumes per domain | **No** | Only DNS packet bytes, not data transfer |
| ECH detection | **No** | Requires both DNS + TCP |
| URL paths / content | **No** | Encrypted in HTTPS |
| Which app made the request | **No** | iOS sandbox blocks process context |

---

## 2. DNS Forwarding Deep Dive

### Packet Flow (step by step)

```
1. App calls getaddrinfo("youtube.com")
2. iOS resolver sends UDP packet to 198.18.0.1:53
3. TUN interface captures it (matches includedRoutes)
4. readPacketsFromTunnel() reads the raw IPv4/UDP/DNS packet
5. Rust engine inspects: extracts domain name, query type, stores in SQLite
6. DNSForwarder.forwardDNSPacket() extracts DNS payload (strips IP+UDP headers)
7. Primary NWUDPSession writes DNS payload to 8.8.8.8:53
   (On retry: secondary session sends to 1.1.1.1:53 instead)
8. DNS server responds with IP addresses
9. setReadHandler callback fires with response data
10. handleResponse() matches by txnID, reconstructs IPv4/UDP packet
11. Rust engine inspects response: extracts resolved IPs for correlation
12. packetFlow.writePackets() delivers response to the app
13. App receives IP addresses, connects directly to the server (no tunnel)
```

### Pacing System

DNS queries are paced at 50ms minimum intervals to prevent NWUDPSession read handler death:

```
Query 1:  sent immediately (0ms)
Query 2:  delayed 50ms
Query 3:  delayed 100ms
Query N:  delayed N*50ms
```

**No cap on delay counter.** Previous versions capped at 10 (500ms max), causing queries 11+ to pile up at the same delay and fire simultaneously — defeating pacing. The uncapped version spreads queries evenly.

**Timeout starts on SEND, not on SCHEDULE.** A query delayed by 3s still gets the full 5s timeout window after it's actually sent.

### Dual-DNS Strategy

- **Fresh queries** → primary session (8.8.8.8)
- **Retries** (same txnID from iOS) → secondary session (1.1.1.1) as failover
- **Collision detection** → if same txnID but different srcPort, SERVFAIL the old query (different app, not a retry)

### Stall Detection & Recovery

NWUDPSession read handlers silently die under burst load. Ring detects this and auto-recovers:

```
Monitor: if (now - lastResponseTime > 5s) && (pendingQueries.count >= 3)
Action:  tear down both sessions → clear all pending → create fresh sessions
Result:  new read handlers, DNS resumes within ~1s
Logged:  dns_STALL event + reconn=N counter in stats
```

---

## 3. NWUDPSession Issues & Mitigations

### The Core Problem

`NWUDPSession` (deprecated iOS 18) has a silent read handler death bug:
- Read handler stops dispatching callbacks after ~80s or >12 queries/sec
- Session remains in `.ready` state — no error, no KVO notification
- Documented in Apple Developer Forums threads 685992, 97979, 696332
- Affects iOS 14+ more severely than earlier versions

### Ring's Mitigations

| Mitigation | How | Effectiveness |
|------------|-----|--------------|
| 50ms send pacing | Limits to 20 queries/sec | Prevents most stalls |
| Stall detection (5s) | Monitors lastResponseTime | Auto-recovers in ~6s |
| Session recreation | Tears down + creates new sessions | Fresh read handlers |
| Dual-DNS failover | Retries go to different server | Diversifies risk |
| SERVFAIL on timeout | Apps fail fast (5s) not hang (30s) | Better UX during stalls |

### DNS Reliability Progression

| Version | Success Rate | Key Change |
|---------|-------------|------------|
| v1 (dual simultaneous) | 14% | Read handler died, never recovered |
| v2 (primary + stall 10s) | 47% | Stall detected but slow recovery |
| v3 (50ms pacing + stall 5s) | 83% | Pacing prevents most stalls |
| v4 (uncapped delay + deferred timeout) | 90%+ expected | Burst queries properly spaced |

---

## 4. Configuration Parameters

All tunable constants in `DNSForwarder`:

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `maxPendingQueries` | 128 | Max concurrent in-flight DNS queries |
| `queryTimeoutSeconds` | 5.0 | Seconds before SERVFAIL synthesized |
| `minSendIntervalMs` | 50.0 | Min ms between DNS sends (20/sec max) |
| `stallDetectionSeconds` | 5.0 | Seconds without response before reconn |
| `maxDatagrams` | 64 | NWUDPSession read handler batch size |

Rust engine constants (`constants.rs`):

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `BATCH_INSERT_SIZE` | 50 | Domains to buffer before SQLite flush |
| `BATCH_FLUSH_INTERVAL_MS` | 500 | Max ms between SQLite flushes |
| `MAX_TCP_FLOWS` | 256 | TCP reassembly flow table capacity |
| `TCP_FLOW_TIMEOUT_SECS` | 30 | TCP flow idle timeout |
| `DNS_CORRELATOR_TTL_SECS` | 300 | DNS-to-IP correlation cache TTL |
| `busy_timeout` | 5000 | SQLite busy timeout (ms) |

---

## 5. Troubleshooting Guide

### Step 1: Pull Diagnostics from Backend

```bash
curl -s 'https://ring-backend-gccf.onrender.com/api/diagnostics?limit=1' | python3 -m json.tool
```

### Step 2: Check DNS Health

Look at the `ipc_stats` line in `tunnel_logs`:
```
ipc_stats: pkts=328 dns=100 sni=0 sent=191 ok=90 timeout=4 drop=0 reconn=1
```

| Metric | Healthy | Problem |
|--------|---------|---------|
| `ok/sent` | >90% | <70% = session stalls |
| `timeout` | <5 | >20 = persistent DNS failure |
| `drop` | 0 | >0 = 128 concurrent query limit hit |
| `reconn` | 0 | >2 = frequent stalls (burst issue) |

### Step 3: Identify Patterns

**Healthy session:** `ok` tracks `sent` closely, no STALL events.

**Burst stall:** `ok` freezes while `sent` climbs → `dns_STALL` → `ok` resumes after reconn.

**Total failure:** `ok=0` after startup → sessions never became ready (network issue).

### Step 4: Common Fixes

| Symptom | Cause | Fix |
|---------|-------|-----|
| YouTube doesn't load | DNS burst kills sessions | Increase minSendIntervalMs |
| Everything works then stops | Read handler death | Stall detection recovers automatically |
| No DNS at all | Session creation failed | Check network connectivity |
| Intermittent empty UI | DatabaseReader busy_timeout too low | Set to 5000ms (matches engine) |

---

## 6. Full VPN Roadmap

### What "Full VPN" Enables

Routing ALL traffic through the tunnel enables the Rust engine's dormant capabilities:

| Feature | Lines of Code | Status |
|---------|--------------|--------|
| TCP reassembly | ~470 | Built, tested, inactive |
| TLS SNI extraction | ~400 | Built, tested, inactive |
| TLS version tracking | ~380 | Built, tested, inactive |
| Byte volume per domain | ~150 | Built, tested, inactive |
| ECH downgrade | ~200 | Built, tested, inactive |

### Architecture Change Required

```
Current:  includedRoutes = [198.18.0.1/32]     → DNS only
Full VPN: includedRoutes = [0.0.0.0/1, 128.0.0.0/1]  → ALL traffic
```

### TCP Relay Layer (the blocker)

With all traffic in the tunnel, non-DNS packets must be forwarded to the internet. This requires a TCP relay:

```
App → TCP SYN → TUN → Rust inspects (SNI, TLS) → TCP Relay → Internet
                                                      ↕
App ← TCP data ← TUN ← response ← TCP Relay ← Internet
```

**Options for TCP relay:**

| Library | Language | Approach | Effort |
|---------|----------|----------|--------|
| `smoltcp` | Rust | User-space TCP/IP stack, integrates with Rust engine | 3-5 days |
| `tun2socks` | Go/C | Battle-tested (Outline VPN uses it) | 2-3 days |
| `lwIP` | C | Lightweight TCP/IP stack, proven on embedded | 3-4 days |
| `NEProvider.createTCPConnection` | Swift | Apple API, per-flow connections | 5-7 days |

**Recommendation:** `smoltcp` in Rust — natural integration with existing packet engine, zero-copy packet handling, well-maintained.

### Implementation Steps

1. Add `smoltcp` to `Cargo.toml`
2. Create `tcp_relay.rs` module: manages TCP flows using smoltcp's TCP socket API
3. For each outbound TCP SYN: create `NEProvider.createTCPConnection` to destination (bypasses tunnel)
4. Relay data bidirectionally between smoltcp TCP socket and NE TCP connection
5. Change `includedRoutes` in tunnel settings
6. Handle UDP relay for non-DNS UDP (QUIC, etc.)

### Battery Impact

Full VPN adds CPU cost for every data packet (inspection + relay). Expected impact:
- DNS-only: <2% additional battery (current)
- Full VPN: 5-15% additional battery during active use
- Idle: minimal difference (no traffic to process)

---

## 7. NWConnection Migration Guide

`NWUDPSession` is deprecated as of iOS 18. Migration to `NWConnection`:

### Current (NWUDPSession)
```swift
let session = provider.createUDPSession(to: endpoint, from: nil)
session.setReadHandler({ datagrams, error in ... }, maxDatagrams: 64)
session.writeDatagram(data) { error in ... }
```

### Target (NWConnection)
```swift
let params = NWParameters.udp
let conn = NWConnection(host: "8.8.8.8", port: 53, using: params)
conn.start(queue: queue)

// Recursive receive loop (replaces persistent setReadHandler)
func scheduleReceive() {
    conn.receiveMessage { data, _, _, error in
        if let data = data { handleResponse(data: data) }
        if error == nil { scheduleReceive() }  // re-arm
    }
}
scheduleReceive()

conn.send(content: dnsPayload, completion: .contentProcessed { error in ... })
```

### Key Differences

| Aspect | NWUDPSession | NWConnection |
|--------|-------------|-------------|
| Receive model | Persistent handler (fire continuously) | One-shot (must re-arm) |
| Tunnel bypass | Automatic via createUDPSession | Route-table based (8.8.8.8 not in includedRoutes) |
| State observation | KVO on "state" | `.stateUpdateHandler` closure |
| Lifecycle | `cancel()` | `.cancel()` |
| iOS support | Deprecated iOS 18, works through iOS 26 | Active, recommended |

### Migration Risk

The recursive `receiveMessage` pattern has the same re-arming risk as `NWConnection.receiveMessage` — if the re-arm fails (transient error), the receive loop dies. Apply the same stall detection pattern.

---

## 8. Battery & Performance

### DNS-Only Tunnel (Current)

- **Battery:** <2% additional in 24 hours (validated by Surge iOS measurements)
- **Latency:** 50ms pacing adds 0-3s to burst DNS resolution
- **Memory:** ~5-10MB in extension process (SQLite + Rust engine + pending queries)
- **CPU:** negligible — ~100-300 DNS queries/hour during active use

### Optimization Techniques

1. **Minimize wakeups:** The `readPackets` completion handler is the primary CPU cost. DNS-only routing minimizes packet volume.
2. **Batch SQLite writes:** The Rust engine buffers 50 domains or 500ms before flushing.
3. **Avoid per-packet allocations:** The 65KB output buffer is pre-allocated once.
4. **Rate-limit debug logging:** Static `ISO8601DateFormatter`, file I/O only on state changes.

### Network Transitions

When the device switches WiFi↔cellular:
- NWUDPSession may silently die (socket bound to old interface)
- Stall detection catches this within 5s and recreates sessions
- `NWConnection` handles path changes better (has `betterPathUpdateHandler`)

---

## 9. Memory Management

### Extension Memory Limit

| iOS Version | Documented Limit | Observed Limit |
|-------------|-----------------|----------------|
| iOS 9-14 | 15 MB | 5-15 MB (varied by device) |
| iOS 15+ | 50 MB | 50 MB (confirmed by Apple DTS) |
| iOS 17-18 | 50 MB | 15 MB reported on low-memory devices |

### Ring's Memory Budget (estimated)

| Component | Size | Notes |
|-----------|------|-------|
| Rust engine struct | ~1 MB | Includes all sub-components |
| SQLite page cache | ~2 MB | `cache_size = -2000` |
| TCP reassembly table | ~256 KB | Pre-allocated 256 entries (dead code) |
| DNS-IP correlator | ~100 KB | Grows with unique IPs |
| RustBridge output buffer | 64 KB | Pre-allocated, for ECH (dead code) |
| Pending DNS queries | ~200 KB | 128 entries max with packet data |
| Debug log I/O | Variable | tunnel_status.txt grows unbounded |
| **Total estimated** | **~4 MB** | Well within 15MB minimum |

### Memory Pressure Handling

Ring uses `DispatchSource.makeMemoryPressureSource` to flush engine buffers on `.warning` and `.critical` pressure events. This reduces peak memory by writing buffered domains to SQLite immediately.

---

## 10. References

### Apple Documentation
- [NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider)
- [TN3120: Expected use cases for Network Extension](https://developer.apple.com/documentation/technotes/tn3120)
- [TN3134: Network Extension provider deployment](https://developer.apple.com/documentation/technotes/tn3134)

### Apple Developer Forums
- [NWUDPSession setReadHandler never fires](https://developer.apple.com/forums/thread/97979)
- [NWUDPSession state behavior](https://developer.apple.com/forums/thread/685992)
- [Network Extension memory limits](https://developer.apple.com/forums/thread/106377)
- [NWConnection replacing NWUDPSession](https://developer.apple.com/forums/thread/129465)

### Open Source References
- [WireGuard iOS](https://github.com/WireGuard/wireguard-apple) — gold standard NEPacketTunnelProvider
- [AdGuard for iOS](https://github.com/AdguardTeam/AdguardForiOS) — DNS filtering via packet tunnel
- [Outline VPN](https://github.com/Jigsaw-Code/outline-apple) — tun2socks integration
- [smoltcp](https://github.com/smoltcp-rs/smoltcp) — Rust user-space TCP/IP stack

### Ring Internal Docs
- `.claude/architecture-review.md` — deep VPN architecture review
- `.claude/dns-reliability-progression.md` — DNS success rate tuning history
- `.claude/edge-cases-audit.md` — 25 edge cases (14 fixed)
- `.claude/edge-case-review.md` — fix quality review
