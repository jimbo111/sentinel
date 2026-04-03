# Sentinel

On-device phishing and malware protection for iOS. Sentinel intercepts DNS queries through a local VPN tunnel, checks every domain against curated threat intelligence feeds, and blocks malicious connections instantly — all without sending your browsing data to the cloud.

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

1. **Network Extension** — intercepts DNS traffic, runs the Rust threat matching engine, blocks malicious domains with sinkhole responses
2. **Main app** — displays the security dashboard, manages threat feeds, handles allowlisting

## Features

- DNS-level threat blocking against 400K+ known phishing, malware, and C2 domains
- Real-time security dashboard with block counter and threat log
- Push notifications when threats are blocked
- Per-domain allowlist for false positive recovery
- Domain monitoring — see every domain your device connects to
- ECH (Encrypted Client Hello) downgrade for security visibility
- Fully on-device — no browsing data transmitted to any server

## Threat Intelligence

| Feed | Coverage | Update Frequency |
|------|----------|-----------------|
| HaGeZi Pro | ~402K domains (ads, trackers, malware) | Daily |
| URLhaus (abuse.ch) | ~20-40K active malware URLs | Daily |

Feeds are downloaded by the app, cached locally, and loaded into the Network Extension on tunnel startup.

## Project structure

```
ring/                              iOS app (Xcode project)
  ring/                            Main app target (SwiftUI)
    Views/
      Threats/                     Security dashboard, threat detail, allowlist
      Connection/                  VPN toggle and status
      Domains/                     Domain history browser
      Stats/                       Analytics and charts
      Settings/                    App configuration
    Services/
      ThreatFeedService            Downloads and caches threat feeds
      ThreatAlertService           Local push notifications for blocks
      DatabaseReader               SQLite queries (domains, alerts, allowlist)
      VPNManager                   NEPacketTunnelProvider lifecycle
    Models/
      ThreatRecord                 Threat alert data model
      DomainRecord                 Domain observation data model
  PacketTunnelExtension/           Network Extension target
    PacketTunnelProvider           DNS interception + forwarding + blocking
    RustBridge                     Swift wrapper around Rust C FFI

rust/packet_engine/                Rust packet engine
  src/
    engine.rs                      Packet processing pipeline + threat integration
    threat_feed.rs                 Bloom filter feed loading (hosts file parser)
    threat_matcher.rs              Multi-feed matching with allowlist bypass
    dns.rs                         DNS query/response parser
    tls.rs                         TLS ClientHello / SNI extractor
    dns_filter.rs                  ECH downgrade (HTTPS RR stripping)
    storage.rs                     SQLite storage (domains, alerts, allowlist)
    lib.rs                         C FFI entry points

scripts/
  build-rust.sh                    Build Rust for a specific iOS target
  build-universal.sh               Build for both device and simulator
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

This compiles `libpacket_engine.a` for both device and simulator, generates the C header via cbindgen, and copies artifacts into the Xcode project.

### 3. Open in Xcode

```bash
open ring/ring.xcodeproj
```

Select your development team in Signing & Capabilities for all targets:
- `sentinel` (main app)
- `PacketTunnelExtension`
- `SentinelWidgetsExtension`

Configure the App Group `group.com.jimmykim.sentinel` in your Apple Developer portal.

### 4. Build and run

Select your iPhone and hit Cmd+R. The app will:
1. Show an onboarding flow
2. Request VPN permission (local tunnel, not a remote proxy)
3. Download threat feeds on first launch
4. Start blocking malicious domains when you browse

## Testing

### Rust engine

```bash
cd rust/packet_engine
cargo test
```

185 tests covering DNS parsing, TLS SNI extraction, TCP reassembly, ECH downgrade, threat feed loading, bloom filter matching, alert dedup, allowlist bypass, and the full processing pipeline.

## Architecture decisions

**Why Rust?** The iOS Network Extension has a 50 MB memory limit (15 MB on some devices). Rust's ownership model prevents leaks, and the bloom filter for 400K domains uses only ~700 KB. The entire engine runs at ~4 MB.

**Why bloom filter instead of HashSet?** A HashSet of 400K domains costs ~29 MB — over half the jetsam budget. The bloom filter at 0.1% false positive rate costs ~700 KB with zero false negatives. False positives are handled via user-facing allowlist.

**Why DNS sinkhole?** Dropping packets causes a 5-second TCP timeout. Returning `A 0.0.0.0` makes the connection fail instantly, giving a better user experience.

**Why UserDefaults for allowlist?** Writing to the shared SQLite from the main app risks `0xDEAD10CC` crashes when iOS suspends the app mid-write. UserDefaults is atomic and cross-process safe.

**Why on-device?** Cloud DNS resolvers (NextDNS, AdGuard DNS) require sending every DNS query to a remote server. Sentinel's local approach means zero browsing data leaves the device — a genuine privacy differentiator.

## Privacy

- All packet analysis runs locally in the Network Extension process
- Domain history and threat alerts are stored in a local SQLite database
- Threat feeds are cached locally — no per-query lookups to external services
- The VPN tunnel is local — traffic is observed and forwarded, not proxied
- DNS queries are forwarded to system DNS servers for resolution

## License

MIT
