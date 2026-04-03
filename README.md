# Ring

A privacy-first iOS app that shows you every domain your device connects to. All traffic analysis runs on-device — nothing leaves your phone.

Ring creates a local VPN tunnel to observe DNS queries, extract domain names, and store them in a local database. No remote servers are involved in the packet inspection pipeline.

## How it works

```
iOS apps send traffic  -->  Local VPN tunnel  -->  Rust packet engine  -->  SQLite
                                                   (DNS parsing)            (on-device)

Internet traffic flows normally. Ring only observes DNS queries.
```

The app consists of three layers:

1. **Rust packet engine** — parses raw IP packets to extract domain names from DNS queries. Compiled as a static C library (`libpacket_engine.a`) and linked into the iOS Network Extension.
2. **iOS Network Extension** — runs as `NEPacketTunnelProvider`, intercepts DNS traffic, passes it through the Rust engine, and forwards it to real DNS servers.
3. **SwiftUI app** — reads the shared SQLite database and displays domains, stats, and settings.

## Features

- Real-time domain monitoring via DNS query interception
- ECH (Encrypted Client Hello) downgrade support — strips ECH configs from DNS HTTPS records
- DNS/IP correlation for passive domain detection
- Local SQLite storage with visit history
- Search, sort, and filter domains
- CSV export
- Privacy-focused: zero data leaves the device

## Project structure

```
ring/                          iOS app (Xcode project)
  ring/                        Main app target (SwiftUI)
    Views/                      Connection, Domains, Stats, Settings, Onboarding
    Services/                   VPNManager, DatabaseReader, APIClient, DarwinNotificationListener
    Models/                     DomainRecord, UserSettings
  PacketTunnelExtension/        Network Extension target
    PacketTunnelProvider.swift   NEPacketTunnelProvider + DNS forwarder
    RustBridge.swift            Swift wrapper around C FFI
    Bridge/packet_engine.h      Auto-generated C header (cbindgen)
  Shared/                       Code shared between both targets
  Frameworks/                   Prebuilt Rust static libraries

rust/packet_engine/             Rust packet engine
  src/
    engine.rs                   Main orchestrator
    ip.rs                       IPv4/IPv6 header parser
    dns.rs                      DNS query + response parser
    tls.rs                      TLS ClientHello / SNI extractor
    tcp_reassembly.rs           Bounded TCP segment reassembly
    dns_filter.rs               ECH downgrade (HTTPS RR stripping)
    ech_correlator.rs           DNS/IP correlation
    storage.rs                  SQLite writer (rusqlite)
    domain.rs                   Domain normalization + noise filtering
    lib.rs                      C FFI entry points

backend/                        Cloud backend (Node.js/Express)
  src/
    routes/                     auth, config, analytics endpoints
    services/                   JWT, Apple auth, user management
    middleware/                  auth, rate limiting, error handling
    db/                         PostgreSQL connection + migrations

scripts/
  build-rust.sh                 Build Rust for a specific iOS target
  build-universal.sh            Build for both device and simulator
  generate-jwt-keys.sh          Generate RSA keys for backend JWT
```

## Requirements

- macOS 14+
- Xcode 15+ (tested on Xcode 26)
- Rust 1.75+ with iOS targets
- Apple Developer account (paid, $99/year)
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

This compiles `libpacket_engine.a` for both device and simulator, and copies the generated C header to the Xcode project.

### 3. Open in Xcode

```bash
open ring/ring.xcodeproj
```

Select your development team in Signing & Capabilities for both targets:
- `ring` (main app)
- `PacketTunnelExtension`

The entitlements for Network Extension and App Groups are already configured in the `.entitlements` files.

### 4. Build and run

Select your iPhone as the build destination and hit Cmd+R. The app will:

1. Show a 3-step onboarding flow
2. Request VPN permission (creates a local tunnel, not a remote proxy)
3. Start capturing DNS queries when you browse

### 5. Backend (optional)

The backend handles auth, feature flags, and anonymous analytics. It's not required for the core domain monitoring functionality.

```bash
cd backend
./scripts/generate-jwt-keys.sh
docker compose up
```

See [backend README](backend/README.md) for details.

## Architecture decisions

**Why Rust for packet parsing?** The iOS Network Extension has a 6 MB memory limit. Rust's ownership model prevents leaks at compile time, and the zero-cost abstractions keep memory usage predictable. The engine typically runs at ~3 MB.

**Why DNS-only capture (not all traffic)?** Forwarding raw IP packets requires a userspace TCP/IP stack. For the MVP, routing only DNS through the tunnel keeps the implementation simple while still capturing the majority of domain connections. SNI extraction from TLS is implemented in the Rust engine and ready for when full-traffic forwarding is added.

**Why SQLite?** Cross-process safe (WAL mode), embedded, zero-config. The Rust engine writes, the Swift app reads. No coordination needed.

**Why no GRDB?** The Swift DatabaseReader uses the raw SQLite3 C API directly (available on iOS), avoiding a third-party dependency. The API surface is small enough that a wrapper library adds complexity without benefit.

## Testing

### Rust engine

```bash
cd rust/packet_engine
cargo test
```

86 tests covering DNS parsing, TLS SNI extraction, TCP reassembly, ECH downgrade, SQLite storage, and the full processing pipeline.

### iOS app

Build and run on a physical device. Network Extensions don't function on the simulator (the app builds but the tunnel can't start).

### Backend

```bash
cd backend
npm test
```

## Privacy

Ring is built around a simple principle: your browsing data stays on your device.

- All packet analysis runs locally in the Network Extension process
- Domain history is stored in a local SQLite database
- The cloud backend (when used) handles only auth and feature flags — zero browsing data is transmitted
- The VPN tunnel is local — traffic is observed and forwarded, not proxied through a remote server
- DNS queries are forwarded to Google DNS (8.8.8.8) for resolution

## License

MIT
