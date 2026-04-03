# Full VPN: TCP Relay Implementation Guide

> Technical guide for implementing the TCP relay layer needed for full VPN mode.

## Why a TCP Relay is Needed

With `includedRoutes = [0.0.0.0/0]`, ALL traffic enters the tunnel. DNS forwarding works the same way. But TCP/UDP data packets need to be forwarded to the internet. You can't just write them back to `packetFlow` (routing loop). You need a user-space TCP stack that:

1. Terminates the app's TCP connection locally (SYN-ACK handshake)
2. Opens a real outbound connection to the destination
3. Relays data bidirectionally

## Recommended Stack: netstack-smoltcp (Rust)

**Why:** Integrates with Ring's existing Rust engine, zero-heap-allocation, iOS-proven, active maintenance.

```
crates.io: netstack-smoltcp
github: automesh-network/netstack-smoltcp
License: Apache/MIT
iOS support: aarch64-apple-ios confirmed
Async API: Tokio-compatible TcpListener/TcpStream/UdpSocket
```

### Memory Budget

| Connections | Buffer per conn | Total |
|-------------|----------------|-------|
| 50 | 16 KB (8+8) | 800 KB |
| 100 | 16 KB | 1.6 MB |
| 100 | 64 KB | 6.4 MB |

Stack overhead: ~50 KB. Ring's total extension budget: 15-50 MB. TCP relay fits comfortably.

## Architecture

```
┌─────────────────────────────────────────────┐
│ PacketTunnelProvider.swift                    │
│                                               │
│  packetFlow.readPackets()                     │
│    │                                          │
│    ├── UDP port 53 → DNSForwarder (existing)  │
│    │                                          │
│    └── Everything else → Rust FFI             │
│         rust_netstack_push(raw_ipv4_frame)    │
│                                               │
│  rust_netstack_poll() → outbound frames       │
│    └── packetFlow.writePackets()              │
└──────────────┬────────────────────────────────┘
               │ FFI
               ▼
┌─────────────────────────────────────────────┐
│ Rust: netstack.rs (new module)               │
│                                               │
│  netstack-smoltcp StackBuilder:               │
│    .tcp_buffer_size(8192)                     │
│    .enable_tcp(true)                          │
│    .enable_udp(true)                          │
│                                               │
│  tcp_listener.accept() → TcpStream            │
│    │                                          │
│    ├── peek first bytes → TLS ClientHello?    │
│    │   └── extract SNI via existing tls.rs    │
│    │   └── extract TLS version                │
│    │   └── record in SQLite                   │
│    │                                          │
│    └── relay_tcp(tun_stream, destination)      │
│         ← needs NWConnection from Swift →     │
└──────────────┬────────────────────────────────┘
               │ Callback to Swift
               ▼
┌─────────────────────────────────────────────┐
│ Swift: create NWConnection to destination    │
│ (bypasses tunnel — not in includedRoutes     │
│  because we use createTCPConnection or       │
│  NWConnection with interface restrictions)   │
└─────────────────────────────────────────────┘
```

## The FFI Bridge Challenge

Rust can't open NWConnection directly. Two patterns:

### Pattern A: Callback (recommended)
```rust
// Rust signals Swift: "need TCP connection to 1.2.3.4:443"
type ConnectCallback = extern "C" fn(dst_ip: u32, dst_port: u16) -> ConnectionHandle;

// Swift implements:
let callback: ConnectCallback = { ip, port in
    let conn = NWConnection(host: ip, port: port, using: .tcp)
    conn.start(queue: relayQueue)
    return register(conn)  // returns opaque handle
}
```

### Pattern B: Channel (simpler FFI)
```rust
// Rust puts relay requests into a queue
// Swift polls the queue and handles connections
// Data flows via shared ring buffers
```

Pattern A is more efficient but more complex FFI. Pattern B is safer for MVP.

## Implementation Steps

### Phase 1: Routing change + passthrough (1 day)
1. Change `includedRoutes` to `[0.0.0.0/1, 128.0.0.0/1]`
2. In `readPacketsFromTunnel`, add: if not DNS, write back to packetFlow (temporary passthrough)
3. Verify: VPN connects, internet works, DNS still intercepted

### Phase 2: smoltcp integration (2 days)
1. Add `netstack-smoltcp` + `tokio` to Cargo.toml
2. Create `netstack.rs`: init StackBuilder, implement Device trait backed by packet buffers
3. FFI: `rust_netstack_push(packet)`, `rust_netstack_poll() -> Vec<packet>`
4. Single-threaded Tokio runtime in Rust

### Phase 3: TCP relay (2 days)
1. Accept TcpStream from smoltcp listener
2. Peek first bytes for TLS ClientHello → extract SNI
3. Record domain + TLS version in SQLite (existing code activated!)
4. Signal Swift to open NWConnection to destination
5. Bidirectional data relay between smoltcp stream and NWConnection

### Phase 4: Byte tracking + cleanup (1 day)
1. Count bytes relayed per domain → update domains.bytes_in/bytes_out
2. UDP relay for non-DNS UDP (QUIC, etc.)
3. Connection idle timeout (60s)
4. Memory cap: max 100 concurrent TCP connections

## What Comes Alive

| Feature | Lines | Currently |
|---------|-------|-----------|
| TCP reassembly | 470 | Dead |
| TLS SNI extraction | 400 | Dead |
| TLS version tracking | 380 | Dead |
| Byte volume per domain | 150 | Dead (DNS bytes only) |
| ECH downgrade | 200 | Dead |
| **Total activated** | **~1600** | |

## Risks

| Risk | Mitigation |
|------|------------|
| Memory pressure (15-50 MB limit) | Cap connections, use small buffers (8KB) |
| Battery drain (all traffic proxied) | Event-driven polling, connection idle timeout |
| TCP meltdown (TCP-over-TCP) | Ring connects directly, no remote proxy — not applicable |
| NWConnection routing loop | Use `createTCPConnection` or interface restrictions |
| Tokio runtime in NE | Single-threaded runtime only (`new_current_thread`) |

## Estimated Effort

| Component | Effort |
|-----------|--------|
| Routing change + passthrough | 1 day |
| smoltcp integration | 2 days |
| TCP relay + SNI extraction | 2 days |
| Byte tracking + UDP relay | 1 day |
| Testing + tuning | 1-2 days |
| **Total** | **~1 week** |
