# Rust Packet Engine

The packet engine (`rust/packet_engine/`) is the core of Ring. It parses network packets, extracts domain names from DNS and TLS traffic, and writes results to SQLite. Compiled as `libpacket_engine.a` (static library) for iOS arm64.

## Module Map

```
src/
├── lib.rs              # FFI entry points (C-callable, panic::catch_unwind on every export)
├── engine.rs           # PacketEngine — main processing loop, batch+flush model
├── ip.rs               # IPv4/IPv6 header parsing
├── dns.rs              # DNS query/response parsing (domain extraction, A/AAAA records)
├── dns_filter.rs       # ECH stripping from SVCB/HTTPS DNS records
├── tls.rs              # TLS ClientHello/SNI parsing
├── tcp_reassembly.rs   # TCP stream reassembly for multi-packet ClientHellos
├── ech_correlator.rs   # DNS-to-IP correlation table (TTL-bounded)
├── domain.rs           # Domain validation, normalization, noise detection
├── storage.rs          # SQLite (WAL mode) — schema creation, batch upsert, cleanup
├── constants.rs        # Tuning parameters (batch size, timeouts, limits)
└── errors.rs           # Error types
```

## Processing Pipeline

```
Raw IP packet
  → ip.rs: parse IPv4/IPv6 header
  → match protocol:
      UDP → dns.rs: parse DNS query → extract domain names → pending_domains buffer
            parse DNS response → ech_correlator.rs: record IP→domain mapping
            dns_filter.rs: strip ECH from HTTPS RRs → ProcessResult::Replace
      TCP → tcp_reassembly.rs: buffer segments per flow
            tls.rs: extract SNI from reassembled ClientHello → pending_domains buffer
  → engine.rs: maybe_flush() → storage.rs: batch_insert() every 500ms or 50 domains
```

## FFI Interface

Every exported function wraps its body in `panic::catch_unwind` to prevent Rust panics from unwinding across the C boundary (which is UB). Errors are reported via a global `LAST_ERROR` mutex.

| Function | Purpose |
|----------|---------|
| `packet_engine_init(db_path) → *mut` | Create engine, open/create SQLite |
| `packet_engine_destroy(engine)` | Drop engine, flush pending |
| `packet_engine_process(engine, pkt, len, out, cap, out_len) → i32` | Process one packet. Returns 0=forward, 1=replace, -1=error |
| `packet_engine_flush(engine)` | Force-flush pending domains to SQLite |
| `packet_engine_set_noise_filter(engine, bool)` | Toggle noise domain filtering |
| `packet_engine_set_ech_downgrade(engine, bool)` | Toggle ECH stripping |
| `packet_engine_get_stats(engine) → EngineStatsFFI` | Return counters (repr(C) struct) |
| `packet_engine_last_error() → *mut c_char` | Consume last error string |
| `packet_engine_free_string(s)` | Free a string returned by `last_error` |

The Swift wrapper (`RustBridge.swift`) mirrors this interface with proper lifecycle management (`shutdown()` nils the handle to prevent double-free in `deinit`).

## Detection Sources

Domains are tagged with how they were discovered:

- **`dns`** — extracted from a DNS query's question section
- **`sni`** — extracted from a TLS ClientHello SNI extension (requires TCP routing, currently inactive)
- **`dns_correlation`** — inferred by matching a TCP connection's destination IP to a prior DNS A/AAAA answer

The source priority hierarchy: `sni` > `dns_correlation` > `dns`. Upserts preserve higher-priority sources.

## ECH Downgrade

Encrypted Client Hello (ECH) hides the SNI from network observers. Ring's countermeasure:

1. **DNS-side (active, working)**: `dns_filter.rs` rewrites DNS responses to strip `ech=` SvcParam from SVCB/HTTPS records. Clients that would have used ECH fall back to plaintext SNI.
2. **TCP-side (built, not active)**: `ech_correlator.rs` maintains a TTL-bounded IP→domain map from DNS responses. When a ClientHello is detected without extractable SNI, the destination IP is looked up in this map.

## Noise Filtering

`domain.rs::is_noise_domain()` checks against ~200+ hardcoded patterns:
- Apple infrastructure (apple.com, icloud.com, mzstatic.com, etc.)
- CDN/analytics (doubleclick.net, googlesyndication.com, etc.)
- mDNS/local (.local, .arpa, .internal)
- Single-label hostnames

Toggled at runtime via `noise_filter_enabled` flag on the engine.

## Storage

SQLite with WAL mode, opened at the App Group shared path. Schema:

```sql
domains (id, domain UNIQUE, first_seen, last_seen, source, visit_count)
visits  (id, domain_id FK, timestamp, source)
settings (key PK, value)
```

Indexes: `idx_domains_domain`, `idx_visits_timestamp`, `idx_visits_domain_id`.

Writes are batched: `pending_domains` buffer flushes every 500ms or when 50 domains accumulate. Each flush is a single transaction with upserts. `Drop` implementation flushes on engine teardown.

## Resource Limits

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `MAX_TCP_FLOWS` | 1024 | Max concurrent TCP reassembly flows |
| `MAX_FLOW_BUFFER_BYTES` | 16 KB | Max buffer per TCP flow |
| `FLOW_TIMEOUT_SECS` | 10s | Idle flow eviction |
| `BATCH_INSERT_SIZE` | 50 | Flush threshold (domain count) |
| `BATCH_FLUSH_INTERVAL_MS` | 500ms | Flush threshold (time) |
| `MAX_CORRELATOR_ENTRIES` | 4096 | DNS-IP correlation table size |
| `CORRELATOR_TTL_SECS` | 300s | IP→domain mapping expiry |

## Build

```bash
./scripts/build-universal.sh   # builds aarch64-apple-ios + aarch64-apple-ios-sim
```

Output: `libpacket_engine.a` (static lib) + `packet_engine.h` (C header via cbindgen). Xcode Run Script phase auto-selects device vs simulator based on `PLATFORM_NAME`.

Dependencies: `rusqlite` (bundled SQLite), `log`, `thiserror`. Build dependency: `cbindgen`.

## Tests

92 tests covering DNS parsing, TLS/SNI extraction, TCP reassembly, ECH filtering, storage upserts, source priority, and engine integration.

```bash
cd rust/packet_engine && cargo test
```
