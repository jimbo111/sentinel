# Sentinel

On-device phishing and malware protection for iOS. Sentinel intercepts DNS queries through a local VPN tunnel, checks every domain against curated threat intelligence feeds (400K+ domains), and blocks malicious connections instantly — all without sending your browsing data to the cloud.

## How it works

```
iOS app makes DNS query
  → Local VPN tunnel intercepts it
  → Rust engine checks domain against bloom filter (400K+ threat domains)
  → Match? → Sinkhole response (0.0.0.0) sent back, connection blocked
  → No match? → Query forwarded to real DNS server normally

All processing happens on-device. Zero browsing data leaves your phone.
```

The app runs as two processes:

1. **Network Extension** — intercepts DNS traffic, runs the Rust threat matching engine, blocks malicious domains with synthesized sinkhole responses
2. **Main app** — security dashboard with VPN control, threat log, domain browser, and feed management

## Features

- **DNS-level threat blocking** — 400K+ known phishing, malware, and C2 domains blocked via bloom filter (~700 KB memory)
- **DNS sinkhole** — blocked domains get an instant `A 0.0.0.0` response instead of a 5-second timeout
- **Unified security dashboard** — VPN toggle, live metrics (domains/packets/queries), threat stats, and recent threats in one view
- **Push notifications** — local alerts when threats are blocked (rate-limited)
- **Per-domain allowlist** — one-tap false positive recovery via UserDefaults IPC
- **Domain transparency** — browse every domain your device connects to, grouped by site, searchable and sortable
- **Activity stats** — 7-day activity chart, top sites, category breakdown
- **Alert dedup** — one alert per domain per session, capped at 10K to prevent memory growth
- **Feed validation** — rejects oversized feeds (>50 MB), HTML error pages, and caps parsing at 1M domains
- **ECH downgrade** — strips Encrypted Client Hello configs for security visibility (opt-in)
- **100% on-device** — no browsing data transmitted to any server, ever

## Threat Intelligence

| Feed | Coverage | Update Frequency | License |
|------|----------|-----------------|---------|
| HaGeZi Pro | ~402K domains | Daily | MIT |
| URLhaus (abuse.ch) | ~20-40K active malware URLs | Daily | CC0 |

Feeds are downloaded by the app on launch, cached in the App Group container, and loaded into the Network Extension's Rust engine on tunnel startup.

## Project structure

```
sentinel/                           iOS app (Xcode project)
  sentinel/                         Main app target (SwiftUI)
    Views/
      Threats/                      Security dashboard, threat detail, allowlist
      Connection/                   Connect button, connection view model
      Domains/                      Domain history browser
      Stats/                        Activity charts and rankings
      Settings/                     App configuration, diagnostics
      Onboarding/                   First-launch permission flow
    Services/
      ThreatFeedService             Downloads and caches threat feeds
      ThreatAlertService            Local push notifications for blocks
      DatabaseReader                SQLite queries (domains, alerts, allowlist)
      VPNManager                    NEPacketTunnelProvider lifecycle
    Models/
      ThreatRecord                  Threat alert data model
      DomainRecord                  Domain observation data model
      SiteRecord                    Grouped site data model
      UserSettings                  User preferences
  PacketTunnelExtension/            Network Extension target
    PacketTunnelProvider            DNS interception + forwarding + sinkhole blocking
    RustBridge                      Swift wrapper around Rust C FFI
  SentinelWidgets/                  Lock screen Live Activity widget
  Shared/
    AppGroupConfig                  App Group IDs, Darwin notification names

rust/packet_engine/                 Rust packet engine (185 tests)
  src/
    engine.rs                       Packet processing pipeline + threat integration
    threat_feed.rs                  Bloom filter feed loading (1M domain cap)
    threat_matcher.rs               Multi-feed matching with allowlist bypass
    dns.rs                          DNS query/response parser
    tls.rs                          TLS ClientHello / SNI extractor
    dns_filter.rs                   ECH downgrade (HTTPS RR stripping)
    storage.rs                      SQLite storage (domains, alerts, allowlist)
    lib.rs                          C FFI entry points (11 functions)

scripts/
  build-universal.sh                Build Rust for device + simulator
  build-rust.sh                     Build Rust for a specific target
```

## Requirements

- macOS 14+
- Xcode 15+
- Rust 1.75+ with iOS targets
- Apple Developer account (Organization enrollment required for VPN apps)
- Physical iPhone for testing (Network Extension doesn't work on simulator)

## Getting started

### 1. Install Rust iOS targets

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
```

### 2. Build the Rust library

```bash
./scripts/build-universal.sh
```

Compiles `libpacket_engine.a` for both device and simulator, generates the C header via cbindgen, and copies artifacts into the Xcode project.

### 3. Open in Xcode

```bash
open sentinel/sentinel.xcodeproj
```

Select your development team in Signing & Capabilities for all targets:
- `sentinel` (main app)
- `PacketTunnelExtension`
- `SentinelWidgetsExtension`

Configure the App Group `group.com.jimmykim.sentinel` in your Apple Developer portal.

### 4. Build and run

Select your iPhone and hit Cmd+R. The app will:
1. Show a 3-step onboarding flow explaining threat protection
2. Request VPN permission (local tunnel, not a remote proxy)
3. Download threat feeds on first launch
4. Start blocking malicious domains when you browse

## Testing

```bash
cd rust/packet_engine
cargo test
```

185 tests covering DNS parsing, TLS SNI extraction, TCP reassembly, ECH downgrade, threat feed loading, bloom filter matching, alert dedup, allowlist bypass, sinkhole response generation, and the full packet processing pipeline.

## Architecture

### Two-process model

```
┌─────────────────────────────────┐
│   Network Extension Process     │
│   (50 MB jetsam limit)          │
│                                 │
│   Rust Engine (~3 MB)           │
│   + Bloom Filter (~700 KB)      │
│   = ~4 MB total                 │
│                                 │
│   DNS query → bloom check       │
│   → match → sinkhole 0.0.0.0   │
│   → alert to SQLite             │
│   → Darwin notify main app      │
└──────────────┬──────────────────┘
               │ SQLite (WAL) + Darwin Notifications + UserDefaults
┌──────────────▼──────────────────┐
│   Main App Process              │
│                                 │
│   Reads alerts from SQLite      │
│   Security dashboard UI         │
│   Feed download + caching       │
│   Allowlist via UserDefaults    │
└─────────────────────────────────┘
```

### Key decisions

**Why Rust?** The Network Extension has a 50 MB memory limit (15 MB on some devices). Rust's ownership model prevents leaks, and the engine runs at ~4 MB total.

**Why bloom filter?** A HashSet of 400K domains costs ~29 MB. The bloom filter at 0.1% FP rate costs ~700 KB with zero false negatives. False positives are handled via allowlist.

**Why DNS sinkhole?** Dropping packets causes a 5-second timeout. Returning `A 0.0.0.0` makes the connection fail instantly.

**Why UserDefaults for allowlist?** Writing to shared SQLite from the main app risks `0xDEAD10CC` crashes on iOS suspension. UserDefaults is atomic and cross-process safe.

**Why on-device?** Cloud DNS resolvers require sending every query to a remote server. Sentinel's local approach means zero browsing data leaves the device.

## Known limitations

- Detection lag: 2-7 days (feeds update daily, phishing domains live <24 hours)
- Bloom filter false positive rate: ~0.1% (~5-10 false alerts/day for typical usage)
- AAAA (IPv6) queries don't receive sinkhole responses (connection times out instead)
- iCloud Private Relay traffic is invisible to the tunnel
- No URL-path-level blocking (DNS layer only)

## Privacy

- All packet analysis runs locally in the Network Extension process
- Domain history and threat alerts are stored in a local SQLite database
- Threat feeds are cached locally — no per-query lookups to external services
- The VPN tunnel is local — traffic is observed and forwarded, not proxied
- The only network requests are two anonymous GET requests to download public threat feed files from CDN (jsDelivr) and abuse.ch
- No user data, device identifiers, or browsing history is ever transmitted
- Privacy manifests (`PrivacyInfo.xcprivacy`) included for both app and extension targets

## License

MIT
