# Ring Frontend — Architecture

## System Overview

Three-layer iOS app: Rust packet engine → C FFI → Swift Network Extension → SwiftUI app.

```
┌────────────────────────────────────────────────────────────┐
│  SwiftUI App                                               │
│  ┌──────────────┐ ┌────────────┐ ┌────────┐ ┌──────────┐  │
│  │ ConnectionView│ │DomainList  │ │StatsView│ │Settings  │  │
│  │ (home, stats) │ │(sites/raw)│ │(bars)   │ │(diag)    │  │
│  └──────┬───────┘ └─────┬──────┘ └────┬───┘ └────┬─────┘  │
│         └───────────────┴─────────────┴──────────┘         │
│                         │ reads                             │
│                         ▼                                   │
│  ┌─────────────────────────────────┐                        │
│  │  SQLite (App Group container)   │                        │
│  │  domains | visits | settings    │                        │
│  └─────────────────────────────────┘                        │
│                         ▲ writes                            │
│                         │                                   │
│  ┌──────────────────────┴─────────────────────────────┐     │
│  │  Network Extension (PacketTunnelProvider)           │     │
│  │                                                     │     │
│  │  ┌──────────────┐    ┌───────────────────────────┐  │     │
│  │  │ DNSForwarder │    │ Rust Packet Engine (FFI)  │  │     │
│  │  │              │    │                           │  │     │
│  │  │ NWConnection │    │ dns.rs     → parse queries│  │     │
│  │  │ to 8.8.8.8   │    │ site_mapper → group sites │  │     │
│  │  │              │    │ storage.rs → write SQLite  │  │     │
│  │  │ Queue until   │    │ dns_filter → ECH downgrade│  │     │
│  │  │ .ready state │    │ engine.rs  → orchestrate  │  │     │
│  │  └──────────────┘    └───────────────────────────┘  │     │
│  └─────────────────────────────────────────────────────┘     │
└────────────────────────────────────────────────────────────┘
```

## DNS Forwarding Flow

```
1. App DNS query → VPN tunnel (port 53 only)
2. PacketTunnelProvider.readPackets → receives raw IPv4/UDP
3. Rust engine.processPacket → extracts domain, computes site_domain
4. DNSForwarder.forwardDNSPacket:
   a. If connection not ready → queue in queuedSends buffer
   b. If connection ready → send via NWConnection to 8.8.8.8
   c. On .ready state → flush all queued sends
   d. On txnID retry → replace stale pending entry (no drop)
5. Response arrives → buildIPv4UDPResponse → writePackets back
6. Rust engine processes response (ECH downgrade, IP correlation)
```

## Site Grouping (Rust `site_mapper.rs`)

Three-layer lookup, first match wins, zero allocation:

| Layer | Entries | Example | Returns |
|-------|---------|---------|---------|
| 1. Known associations | 84 | `ytimg.com` | `youtube.com` |
| 2. Infra filter | 24 | `googleapis.com` | `_infra` (hidden) |
| 3. eTLD+1 fallback | 20 multi-part TLDs | `www.bbc.co.uk` | `bbc.co.uk` |

Computed at INSERT time, stored in `site_domain` column.

## Client Services

| Service | Purpose |
|---------|---------|
| `ConsentService` | Sends privacy consent to backend, retries on failure |
| `TelemetryService` | Syncs site data to backend (consent-gated) |
| `ConfigService` | Fetches resolved associations from backend, caches locally |
| `CategoriesService` | Client-side domain categorization (14 categories, ~120 domains) |
| `DatabaseReader` | Reads SQLite for domains, sites, stats, visits |
| `LogCollector` | Shared debug log file in App Group for diagnostics |

## UI Design System (`Theme.swift`)

- Card-based layout via `.cardStyle()` modifier (16pt corners, subtle shadow)
- `SectionHeader` component with optional count badge
- Colors: lavender, amber, lime, muted purple accent
- StatsView: full-screen stacked proportional bars (tap to expand)
- CategoriesView: proportional color bar + category cards

## Database Schema

```sql
domains:  id, domain, first_seen, last_seen, source, visit_count, site_domain
visits:   id, domain_id, timestamp, source
settings: key, value
```

Column names must match exactly between Rust (writer) and Swift (reader).
