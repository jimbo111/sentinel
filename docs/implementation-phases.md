# Implementation Phases

## Overview

Five phases, each producing a testable, demo-able milestone. Each phase builds on the previous one. Estimated total: 10-14 weeks for a solo developer.

---

## Phase 1: Headless Rust Packet Parser (Weeks 1-3)

**Goal**: A standalone Rust library that can parse raw IP packets and extract domain names from DNS queries and TLS SNI. Fully testable on macOS without any iOS code.

### Deliverables

| # | Task | File(s) | Done When |
|---|------|---------|-----------|
| 1.1 | Set up Rust project with `Cargo.toml`, `staticlib` crate type | `rust/packet_engine/Cargo.toml` | `cargo build` succeeds |
| 1.2 | Implement IPv4/IPv6 header parser | `src/ip.rs` | Unit tests pass with captured packet fixtures |
| 1.3 | Implement DNS query parser | `src/dns.rs` | Extracts "google.com" from a real DNS query packet |
| 1.4 | Implement TLS ClientHello SNI extractor | `src/tls.rs` | Extracts "amazon.com" from a real TLS handshake capture |
| 1.5 | Implement TCP reassembly buffer | `src/tcp_reassembly.rs` | Handles multi-segment ClientHello, LRU eviction |
| 1.6 | Implement DomainRecord + normalization | `src/domain.rs` | Trailing dots stripped, noise filtered, IP literals rejected |
| 1.7 | Implement SQLite storage module | `src/storage.rs` | Batch insert + UPSERT works, WAL mode enabled |
| 1.8 | Implement PacketEngine orchestrator | `src/engine.rs` | Full pipeline: raw bytes → SQLite row |
| 1.9 | Create test fixtures | `tests/fixtures/` | DNS, TLS, fragmented packets as .bin files |
| 1.10 | Integration test | `tests/integration_test.rs` | End-to-end test passes |

### Acceptance Criteria

```bash
# Build for macOS (for testing)
cargo build --release
cargo test

# All tests pass, including:
# - DNS query parsing (A, AAAA records)
# - TLS SNI extraction (TLS 1.2 and 1.3 ClientHello)
# - TCP reassembly (single and multi-segment)
# - Domain normalization and filtering
# - SQLite batch insert with UPSERT
# - Full pipeline integration test
```

### How to Generate Test Fixtures

```bash
# Capture a DNS query to google.com
sudo tcpdump -i en0 -c 1 -w /tmp/dns.pcap 'udp dst port 53'
# Then browse to google.com

# Capture a TLS ClientHello
sudo tcpdump -i en0 -c 3 -w /tmp/tls.pcap 'tcp dst port 443'
# Then browse to amazon.com

# Extract raw IP packets from pcap using Python:
python3 scripts/generate-test-fixtures.py /tmp/dns.pcap tests/fixtures/dns_query_google.bin
```

---

## Phase 2: Cross-Platform Bindings (Weeks 3-4)

**Goal**: The Rust library compiles for `aarch64-apple-ios`, exposes a C ABI, and can be called from Swift.

### Deliverables

| # | Task | File(s) | Done When |
|---|------|---------|-----------|
| 2.1 | Add `cbindgen` build script | `build.rs`, `cbindgen.toml` | `cargo build` generates `packet_engine.h` |
| 2.2 | Implement FFI entry points | `src/lib.rs` | All `extern "C"` functions: init, process, flush, destroy, stats, errors |
| 2.3 | Add panic catching on all FFI functions | `src/lib.rs` | No panic can cross FFI boundary |
| 2.4 | Cross-compile for iOS | `scripts/build-rust.sh` | `libpacket_engine.a` for `aarch64-apple-ios` |
| 2.5 | Cross-compile for iOS Simulator | `scripts/build-rust.sh` | `libpacket_engine.a` for `aarch64-apple-ios-sim` |
| 2.6 | Create Xcode project skeleton | `DomainGuard.xcodeproj` | Two targets: app + extension |
| 2.7 | Add bridging header + link static lib | Xcode config | Extension target compiles and links `libpacket_engine.a` |
| 2.8 | Implement `RustBridge.swift` | `PacketTunnelExtension/RustBridge.swift` | Swift wrapper compiles, calls init/process/destroy |
| 2.9 | Write Swift-side smoke test | — | Can call `RustPacketEngine(dbPath:)` → `processPacket()` → `shutdown()` without crash |

### Acceptance Criteria

```bash
# Rust cross-compilation
./scripts/build-rust.sh aarch64-apple-ios
./scripts/build-rust.sh aarch64-apple-ios-sim

# Xcode project builds with no linker errors
xcodebuild -scheme DomainGuard -sdk iphonesimulator -configuration Debug build

# Swift code can instantiate and call the Rust engine
# (verified via unit test or playground)
```

---

## Phase 3: Native iOS VPN Hooks (Weeks 4-7)

**Goal**: A working on-device VPN that intercepts traffic, extracts domains, and stores them in SQLite. No UI yet — verify via Console.app logs and SQLite browser.

### Deliverables

| # | Task | File(s) | Done When |
|---|------|---------|-----------|
| 3.1 | Request NE entitlement from Apple | Apple Developer Portal | Entitlement granted (can take 1-3 business days) |
| 3.2 | Configure App Group | Xcode capabilities | Both targets share `group.com.yourcompany.domainguard` |
| 3.3 | Set up entitlements files | `.entitlements` files | Packet Tunnel + App Groups in both targets |
| 3.4 | Implement `PacketTunnelProvider` | `PacketTunnelExtension/PacketTunnelProvider.swift` | `startTunnel` / `stopTunnel` work |
| 3.5 | Configure tunnel network settings | `PacketTunnelProvider.swift` | All traffic routes through tunnel (IPv4 + IPv6) |
| 3.6 | Implement packet read/write loop | `PacketTunnelProvider+PacketFlow.swift` | Packets flow through: read → Rust → write |
| 3.7 | Implement `VPNManager` (app side) | `DomainGuard/Services/VPNManager.swift` | Can start/stop tunnel programmatically |
| 3.8 | Implement `AppGroupConfig` (shared) | `Shared/AppGroupConfig.swift` | Shared DB path, notification name |
| 3.9 | Implement IPC messages | `PacketTunnelProvider.swift` | flush + stats commands work via `sendProviderMessage` |
| 3.10 | Implement Darwin notification | Extension + App | Extension pings app when new domains are written |
| 3.11 | Test on physical device | — | VPN connects, domains appear in SQLite |

### Acceptance Criteria

```
1. Install app on physical iPhone
2. Tap a "Connect" button (temporary, hardcoded)
3. iOS shows VPN permission dialog → approve
4. VPN icon appears in status bar
5. Browse to several websites (Safari, Chrome)
6. Connect iPhone to Mac, open Console.app
7. See log messages: "DNS domain: google.com", "SNI domain: amazon.com"
8. Use SQLite browser to inspect domains.sqlite in App Group container
9. Tap "Disconnect" → VPN icon disappears
10. Internet works normally throughout (no packet drops, no speed degradation)
```

**Critical testing**:
- Network Extension does NOT crash (stay within 6 MB memory)
- No packet loss (all packets forwarded after inspection)
- Battery impact is minimal (monitor in Settings → Battery)
- Hot path (`processPacket`) takes < 10μs per packet (measure via `os_signpost`)

---

## Phase 4: Local Storage & UI (Weeks 7-10)

**Goal**: Complete SwiftUI app with domain list, stats, settings, and real-time updates.

### Deliverables

| # | Task | File(s) | Done When |
|---|------|---------|-----------|
| 4.1 | Add GRDB.swift via SPM | Xcode | Package resolves, app compiles |
| 4.2 | Implement `DatabaseReader` | `Services/DatabaseReader.swift` | Can read domains from shared SQLite |
| 4.3 | Implement `DarwinNotificationListener` | `Services/DarwinNotificationListener.swift` | App receives pings when new data available |
| 4.4 | Build `ConnectionView` + `ConnectButton` | `Views/Connection/` | Big connect button, status display, stats cards |
| 4.5 | Build `DomainListView` + `DomainRowView` | `Views/Domains/` | Searchable, sortable list of domains |
| 4.6 | Build `DomainDetailView` | `Views/Domains/` | Visit history for a specific domain |
| 4.7 | Build `DomainListViewModel` | `Views/Domains/` | Reactive updates via GRDB ValueObservation |
| 4.8 | Build `StatsView` with Charts | `Views/Stats/` | Bar chart (domains/day), top domains, detection breakdown |
| 4.9 | Build `SettingsView` | `Views/Settings/` | Toggles, retention picker, export, clear data |
| 4.10 | Implement CSV export | `SettingsViewModel.swift` | Export domain list as CSV to Files app |
| 4.11 | Implement data cleanup | Engine + SettingsVM | Old visits auto-deleted per retention setting |
| 4.12 | Build `MainTabView` | `Views/MainTabView.swift` | 4-tab layout: Home, Domains, Stats, Settings |
| 4.13 | Build onboarding flow | `Views/Onboarding/` | 3-step first-launch explanation + VPN permission |
| 4.14 | Polish animations and transitions | — | Smooth connect/disconnect animation, list transitions |

### Acceptance Criteria

```
1. App launches with onboarding on first run
2. Onboarding explains the app and requests VPN permission
3. Home tab: Connect button works, shows live stats
4. Domains tab: Shows real-time list of visited domains
5. Domains update within 500ms of visiting a new site
6. Search works (filters by domain name)
7. Sort works (recent, most visited, alphabetical)
8. Tapping a domain shows detail with visit history
9. Stats tab: Charts populate with real data
10. Settings: All toggles persist across app restarts
11. Export: CSV file opens in Files app
12. Clear data: Confirmation dialog, then wipes DB
```

---

## Phase 5: ECH Fallback (Weeks 10-12)

**Goal**: Build ECH detection and DNS/IP correlation into the Rust engine, gated behind a feature flag.

### Deliverables

| # | Task | File(s) | Done When |
|---|------|---------|-----------|
| 5.1 | Add ECH detection to TLS parser | `src/tls.rs` | `detect_ech()` identifies ECH, GREASE, and normal ClientHello |
| 5.2 | Add DNS response parsing | `src/dns.rs` | `parse_dns_response()` extracts domain → IP mappings |
| 5.3 | Implement DNS/IP correlator | `src/ech_correlator.rs` | Bounded HashMap, 5-min TTL, LRU eviction |
| 5.4 | Integrate ECH fallback into engine | `src/engine.rs` | Modified `handle_tcp` with ECH-aware processing |
| 5.5 | Add `DnsCorrelation` detection source | `src/domain.rs` | New variant, persists in SQLite |
| 5.6 | Add ECH metrics to stats | `src/engine.rs` + FFI | `ech_connections`, `ech_resolved`, `ech_unresolved` |
| 5.7 | Gate behind feature flag | `src/engine.rs` | ECH processing can be enabled/disabled at runtime |
| 5.8 | Update Swift stats display | Stats UI | Show ECH metrics if feature is enabled |
| 5.9 | Set up cloud backend (basic) | `backend/` | Config endpoint returns feature flags |
| 5.10 | Implement `APIClient` | `Services/APIClient.swift` | Fetches remote config on app launch |
| 5.11 | Test with ECH-enabled sites | — | Verify domains are still detected via DNS correlation |

### Acceptance Criteria

```
1. Visit cloudflare.com (which uses ECH)
2. Engine detects ECH in ClientHello
3. Engine correlates via DNS: cloudflare.com resolved to IP X, TLS to IP X → cloudflare.com
4. Domain appears in list with "dns_corr" source badge
5. ECH metrics visible in stats (when feature flag enabled)
6. Feature can be toggled via remote config without app update
7. No performance regression (ECH detection adds < 1μs per packet)
```

---

## Phase 5.5 (Optional): Cloud Backend Polish (Weeks 12-14)

| # | Task | Notes |
|---|------|-------|
| 5.5.1 | Sign in with Apple integration | Full auth flow, JWT tokens |
| 5.5.2 | Anonymous analytics pipeline | Event ingestion, basic dashboard |
| 5.5.3 | Crash reporting (Sentry) | dSYM upload, symbolication |
| 5.5.4 | App Store submission prep | Privacy labels, screenshots, description |
| 5.5.5 | TestFlight beta distribution | Internal + external testers |

---

## Risk Register

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Apple rejects NE entitlement request | Blocks Phase 3 | Low (10%) | Apply early (Phase 1). Have backup plan using NEDNSProxyProvider (less capable but easier to get approved) |
| Network Extension 6 MB memory limit | Crashes in production | Medium (30%) | Budget analysis done (see `local-packet-engine.md`). Monitor with `os_proc_available_memory()`. Aggressive LRU eviction. |
| TLS ClientHello spans > 16 KB | Missed SNI extraction | Very Low (5%) | 16 KB limit is generous. Modern ClientHello is typically 200-600 bytes. Log and monitor misses. |
| DNS-over-HTTPS adoption breaks DNS layer | Fewer domains detected | Medium (growing) | ECH fallback (Phase 5) + our tunnel forces standard DNS via `NEDNSSettings` |
| App Store review: "VPN apps require specific permissions" | Rejection | Medium (25%) | Clearly document that this is a local analysis tool, not a remote proxy VPN. Include detailed privacy description. |
| Battery drain complaints | Poor reviews | Medium (30%) | Optimize Rust engine for minimal CPU. Batch SQLite writes. Profile with Instruments Energy gauge. |

---

## Dependency Graph

```
Phase 1 (Rust engine)
    │
    ▼
Phase 2 (FFI bindings)
    │
    ├───────────────────┐
    ▼                   ▼
Phase 3 (VPN hooks)   Phase 5 starts (ECH detection in Rust, no iOS dependency)
    │                   │
    ▼                   │
Phase 4 (UI)            │
    │                   │
    ▼                   ▼
Phase 5 integration  ◄──┘
    │
    ▼
Phase 5.5 (Polish & Ship)
```

Note: Phase 5's Rust-only work (ECH detection, DNS response parsing, IP correlation) can begin in parallel with Phase 3 since it's pure Rust with no iOS dependencies. The integration into the engine and iOS UI happens after Phase 4.
