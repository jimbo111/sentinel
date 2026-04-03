# Rust Packet Engine Internals

> Technical reference for the Rust packet engine that processes DNS queries on-device.

## Module Map

```
packet_engine/src/
├── lib.rs              FFI exports (C ABI for Swift)
├── engine.rs           PacketEngine: main packet processing + flush logic
├── dns.rs              DNS query/response parsing
├── domain.rs           DomainRecord model + noise filtering
├── site_mapper.rs      Site grouping (CDN → parent site mapping)
├── storage.rs          SQLite storage (domains, visits, domain_ips, dns_query_types)
├── tls.rs              TLS ClientHello parsing (SNI + version extraction)
├── tcp_reassembly.rs   TCP flow tracking for multi-segment ClientHello
├── ip.rs               IPv4/IPv6 header parsing
├── ech_correlator.rs   DNS-to-IP correlation (for ECH + byte tracking)
├── constants.rs        Tunable parameters
└── errors.rs           EngineError enum
```

## Packet Processing Flow

```
process_packet(raw_ip_bytes)
    │
    ├── ip::parse_ip_header()         → IpHeader (version, addrs, protocol, payload offset)
    │
    ├── Byte tracking (if DNS-IP correlator has mapping)
    │   ├── lookup dst_addr → domain? → accumulate bytes_out
    │   └── lookup src_addr → domain? → accumulate bytes_in
    │
    ├── if UDP + dst_port == 53:
    │   ├── dns::parse_dns_query() → Vec<DomainRecord> (A/AAAA only)
    │   ├── dns::parse_dns_query_types() → Vec<(domain, qtype)> (all types)
    │   ├── dns::parse_dns_response() → Vec<(domain, ip)> (for correlator)
    │   ├── Push to pending_domains, pending_query_types, pending_domain_ips
    │   └── Return ProcessResult::Forward
    │
    ├── if TCP + dst_port == 443:
    │   ├── tcp_reassembly::process_segment() → may return DomainRecord with TLS version
    │   ├── Push to pending_domains if SNI extracted
    │   └── Return ProcessResult::Forward or ProcessResult::Replace (ECH downgrade)
    │
    └── maybe_flush() → batch write to SQLite if threshold reached
```

**Note:** TCP processing (port 443) is built and tested but inactive in production because the current tunnel routing only captures DNS packets.

## SQLite Schema

### `domains` table
```sql
id          INTEGER PRIMARY KEY AUTOINCREMENT
domain      TEXT UNIQUE NOT NULL      -- e.g. "youtube.com"
first_seen  INTEGER NOT NULL          -- Unix ms timestamp
last_seen   INTEGER NOT NULL          -- Unix ms timestamp
source      TEXT NOT NULL             -- "dns", "sni", or "dns_correlation"
visit_count INTEGER NOT NULL DEFAULT 1
site_domain TEXT                      -- e.g. "youtube.com" (eTLD+1 or known association)
tls_version TEXT                      -- e.g. "1.3" (NULL until TCP routing enabled)
bytes_in    INTEGER NOT NULL DEFAULT 0
bytes_out   INTEGER NOT NULL DEFAULT 0
```

### `visits` table
```sql
id        INTEGER PRIMARY KEY AUTOINCREMENT
domain_id INTEGER REFERENCES domains(id)
timestamp INTEGER NOT NULL
source    TEXT NOT NULL
```

### `domain_ips` table
```sql
id         INTEGER PRIMARY KEY AUTOINCREMENT
domain     TEXT NOT NULL
ip         TEXT NOT NULL
first_seen INTEGER NOT NULL
last_seen  INTEGER NOT NULL
UNIQUE(domain, ip)
```

### `dns_query_types` table
```sql
id              INTEGER PRIMARY KEY AUTOINCREMENT
domain          TEXT NOT NULL
query_type      INTEGER NOT NULL      -- DNS QTYPE number (1=A, 28=AAAA, 65=HTTPS, etc.)
query_type_name TEXT NOT NULL         -- Human-readable name
first_seen      INTEGER NOT NULL
last_seen       INTEGER NOT NULL
query_count     INTEGER NOT NULL DEFAULT 1
UNIQUE(domain, query_type)
```

### `settings` table
```sql
key   TEXT PRIMARY KEY
value TEXT
```

## Site Mapping (3-layer)

`site_mapper::map_to_site(domain)` returns `Cow<'_, str>`:

1. **Known associations** (~80 tuples): suffix match
   - `ytimg.com` → `youtube.com`, `fbcdn.net` → `facebook.com`, etc.
   - Returns `Cow::Borrowed` — zero allocation

2. **Infrastructure filter** (~25 suffixes): shared CDN/tracking domains
   - `googleapis.com`, `cloudfront.net`, `akamaiedge.net`, etc.
   - Returns `Cow::Borrowed("_infra")`

3. **eTLD+1 fallback**: extract registrable domain
   - Checks `MULTI_PART_TLDS` (~34 entries: `.co.uk`, `.gov.au`, etc.)
   - `www.bbc.co.uk` → `bbc.co.uk` (3 labels)
   - `api.stripe.com` → `stripe.com` (2 labels)
   - Returns `Cow::Borrowed` — substring slice, zero allocation

## Noise Filtering

`domain.rs::is_noise_domain()` — drops infrastructure domains before storage:
- Suffixes: `arpa`, `local`, `internal`, `in-addr.arpa`, `ip6.arpa`
- CDN: `cloudfront.net`, `akamaiedge.net`, `akamaihd.net`, `akadns.net`
- Tracking: `1e100.net` (Google infrastructure)

Applied in `engine.rs::handle_udp()` before pushing to pending buffers.

## FFI Boundary (lib.rs)

| Function | Swift calls | Purpose |
|----------|------------|---------|
| `packet_engine_create` | `RustPacketEngine.init()` | Create engine with DB path |
| `packet_engine_process` | `processPacket()` | Process one IP packet |
| `packet_engine_flush` | `flush()` | Force write pending data to SQLite |
| `packet_engine_get_stats` | `getStats()` | Read engine statistics |
| `packet_engine_cleanup` | `cleanupOldData()` | Delete old visits |
| `packet_engine_destroy` | `deinit` | Free engine memory |
| `packet_engine_set_noise_filter` | `setNoiseFilter()` | Toggle noise filtering |
| `packet_engine_set_ech_downgrade` | `setEchDowngrade()` | Toggle ECH stripping |

All FFI functions use `panic::catch_unwind` to prevent Rust panics from unwinding into Swift (undefined behavior). Errors are stored in a thread-local `LAST_ERROR` and retrievable via `packet_engine_last_error`.

## Batch Flush Strategy

The engine buffers data in memory and flushes to SQLite periodically:

- **Trigger:** `pending_domains.len() >= 50` OR `elapsed >= 500ms`
- **Flush order:** domains → domain_ips → query_types → bytes (domains first so byte UPDATE finds existing rows)
- **Transaction:** each buffer uses a separate SQLite transaction
- **On error:** data is lost (logged, not re-queued — prevents infinite retry on persistent failure)

## Test Coverage

140 tests covering:
- DNS parsing (query, response, all record types, compression pointers, truncation safety)
- TLS version extraction (1.0, 1.1, 1.2, 1.3, supported_versions extension)
- TCP reassembly (single segment, multi-segment, eviction, timeout)
- Storage (upsert semantics, COALESCE on tls_version, byte accumulation, migration safety)
- Site mapper (known associations, infrastructure, eTLD+1, multi-part TLDs)
- Domain filtering (noise rejection, IP literal rejection, length limits)

Run: `cd rust/packet_engine && cargo test`
