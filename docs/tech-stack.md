# Tech Stack

## Overview

| Layer | Language | Why |
|-------|----------|-----|
| UI / App | Swift 5.9+ / SwiftUI | Native iOS, first-class `NetworkExtension` support |
| Packet Engine | Rust 1.75+ (stable) | Zero-cost abstractions, no GC, deterministic memory, compiles to `aarch64-apple-ios` static lib |
| FFI Bridge | C ABI (Rust `extern "C"`) + Swift C interop | Simplest, most stable FFI boundary on Apple platforms |
| Local Storage | SQLite 3.x (via `rusqlite` in Rust, `GRDB.swift` in Swift) | Cross-process safe, WAL mode, embedded, zero-config |
| Cloud Backend | Node.js (Express) or Go | Lightweight REST API for auth/config (pick per team familiarity) |
| Infrastructure | AWS (or any cloud) | Small scale: single EC2 + RDS or managed Postgres |

---

## iOS App Layer

### Language & Frameworks

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| UI framework | SwiftUI | iOS 16+ | Declarative UI for domain list, settings, stats |
| App lifecycle | Swift/UIKit `AppDelegate` | — | Required for Network Extension lifecycle hooks |
| VPN management | `NetworkExtension.framework` | iOS 16+ | `NETunnelProviderManager`, `NEPacketTunnelProvider` |
| Shared storage | App Groups | — | `group.com.yourapp.vpn` container for SQLite + UserDefaults |
| Database (read) | GRDB.swift | 6.x | Type-safe SQLite reads from shared DB. ValueObservation for reactive UI updates |
| Networking | URLSession | — | Cloud backend API calls (auth, config) |
| Auth | AuthenticationServices | — | Sign in with Apple |
| Notifications | Darwin Notifications (`CFNotificationCenter`) | — | Lightweight IPC: extension → app "new data" pings |
| Logging | `os.log` / OSLog | — | Unified logging for both app and extension |

### Minimum Deployment Target

**iOS 16.0**

Rationale: iOS 16 is the minimum that provides stable `NEPacketTunnelProvider` APIs with the packet flow improvements we need. As of 2025, iOS 16+ covers >95% of active devices.

### Xcode & Build

| Tool | Version |
|------|---------|
| Xcode | 15.0+ |
| Swift | 5.9+ |
| Build system | Xcode + custom Run Script phases for Rust compilation |

---

## Rust Packet Engine Layer

### Toolchain

| Component | Version | Notes |
|-----------|---------|-------|
| Rust | 1.75+ stable | `rustup target add aarch64-apple-ios` |
| Cargo | (bundled) | Workspace with single library crate |
| Target triple | `aarch64-apple-ios` | ARM64 for physical devices |
| Simulator target | `aarch64-apple-ios-sim` | For Apple Silicon Macs |
| Output | Static library (`libpacket_engine.a`) | Linked into the Network Extension target |
| C header | Auto-generated via `cbindgen` | Consumed by Swift via bridging header |

### Rust Dependencies (Cargo.toml)

```toml
[package]
name = "packet_engine"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
# DNS wire format parsing
dns-parser = "0.8"              # Lightweight DNS packet parser

# SQLite
rusqlite = { version = "0.31", features = ["bundled"] }
# "bundled" compiles SQLite from source — guarantees version consistency
# and avoids linking against iOS system SQLite (which lacks some features)

# Logging
log = "0.4"
oslog = "0.2"                   # Bridges Rust `log` to Apple's os_log

# Error handling
thiserror = "1.0"

# Time
chrono = { version = "0.4", default-features = false, features = ["clock"] }

[build-dependencies]
cbindgen = "0.26"               # Auto-generates C header from Rust FFI functions

[profile.release]
opt-level = "s"                 # Optimize for size (critical for iOS extension)
lto = true                      # Link-time optimization
codegen-units = 1               # Maximum optimization
strip = true                    # Strip debug symbols
panic = "abort"                 # No unwinding runtime (saves ~200KB)
```

### Key Crate Choices Explained

| Crate | Why this one |
|-------|-------------|
| `dns-parser` | Minimal, no-alloc-friendly DNS wire format parser. Handles standard query records. No async runtime bloat. |
| `rusqlite` with `bundled` | Compiles SQLite from C source into the static lib. This avoids depending on the iOS system SQLite version and gives us WAL mode + all pragma control. |
| `cbindgen` | Build-time tool that reads Rust `extern "C"` functions and generates a `.h` file. This header is consumed by Swift's bridging header — zero manual header maintenance. |
| `thiserror` | Derive macro for error enums. Zero runtime cost, clean error propagation. |
| `oslog` | Routes Rust's `log::info!()` etc. to Apple's unified logging system. Visible in Console.app alongside Swift logs. |

### What We Do NOT Use

| Crate / Pattern | Why excluded |
|-----------------|-------------|
| `tokio` / `async-std` | No async runtime. The extension's packet loop is synchronous (`readPackets` → process → `writePackets`). An async runtime adds ~500KB binary size and complexity for zero benefit here. |
| `serde` / `serde_json` | No JSON serialization in the hot path. Domain records go straight to SQLite via parameterized queries. |
| `libc` | We don't make raw syscalls. All I/O goes through the iOS-provided packet flow or SQLite. |
| `std::net` | We parse raw packet bytes, not socket APIs. |

---

## FFI Bridge

| Component | Technology |
|-----------|-----------|
| ABI | C ABI (`extern "C" fn`) |
| Header generation | `cbindgen` (build.rs) |
| Swift consumption | Bridging header in Network Extension target |
| Data passing | Raw pointers (`*const u8`, `usize`) for packets; C strings for paths |
| Memory ownership | Caller owns packet buffers (iOS allocates, Rust borrows). Rust owns its internal state. |

See `cross-platform-bindings.md` for full FFI API specification.

---

## Local Storage

| Component | Technology | Notes |
|-----------|-----------|-------|
| Database | SQLite 3.45+ (bundled via rusqlite) | Compiled into Rust static lib |
| Writer | `rusqlite` (Rust) | Network Extension process |
| Reader | `GRDB.swift` (Swift) | Main app process |
| File location | `{AppGroupContainer}/domains.sqlite` | Shared via App Group |
| Journal mode | WAL | Concurrent read/write across processes |
| Sync mode | NORMAL | Balance between safety and performance |

See `data-storage.md` for full schema and query specifications.

---

## Cloud Backend

### Option A: Node.js (Recommended for small scale)

| Component | Technology |
|-----------|-----------|
| Runtime | Node.js 20 LTS |
| Framework | Express 4.x |
| Database | PostgreSQL 16 (AWS RDS or equivalent) |
| Auth | JWT (RS256) + Sign in with Apple server-side validation |
| Hosting | Single EC2 t3.small or equivalent |
| API style | REST (JSON) |

### Option B: Go (If team prefers)

| Component | Technology |
|-----------|-----------|
| Runtime | Go 1.22+ |
| Framework | `net/http` + `chi` router |
| Database | PostgreSQL 16 |
| Auth | Same JWT approach |

### Cloud Infrastructure

| Service | Purpose | Provider |
|---------|---------|----------|
| Compute | API server | AWS EC2 / Fly.io / Railway |
| Database | User accounts, config | PostgreSQL (managed) |
| Auth | Token signing | Self-managed JWT keys |
| Crash reporting | Symbolicated crash logs | Sentry (free tier) |
| Analytics | Anonymous usage metrics | PostHog (self-hosted) or Mixpanel (free tier) |
| CI/CD | Build + test pipeline | GitHub Actions |

---

## Build & CI Pipeline

### iOS Build

```
1. cargo build --target aarch64-apple-ios --release
   → Produces: target/aarch64-apple-ios/release/libpacket_engine.a
   → Produces: target/packet_engine.h  (via cbindgen)

2. Copy .a and .h into Xcode project's vendor directory

3. xcodebuild -scheme "DomainGuard" -configuration Release
   → Links libpacket_engine.a into Network Extension target
   → Produces: DomainGuard.app (with embedded .appex)
```

### Automated via Xcode Run Script Phase

```bash
# In Network Extension target → Build Phases → Run Script (before Compile Sources)
cd "${SRCROOT}/rust/packet_engine"

if [ "$PLATFORM_NAME" = "iphonesimulator" ]; then
    RUST_TARGET="aarch64-apple-ios-sim"
else
    RUST_TARGET="aarch64-apple-ios"
fi

cargo build --target "$RUST_TARGET" --release

cp "target/$RUST_TARGET/release/libpacket_engine.a" "${SRCROOT}/Frameworks/"
cp "target/packet_engine.h" "${SRCROOT}/NetworkExtension/Bridge/"
```

### CI (GitHub Actions)

```yaml
jobs:
  build-rust:
    runs-on: macos-14  # Apple Silicon runner
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: aarch64-apple-ios,aarch64-apple-ios-sim
      - run: cargo build --target aarch64-apple-ios --release
      - run: cargo test  # Run unit tests on host

  build-ios:
    needs: build-rust
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4
      - run: xcodebuild -scheme DomainGuard -sdk iphoneos -configuration Release
```

---

## Version Compatibility Matrix

| Component | Minimum | Recommended | Max Tested |
|-----------|---------|-------------|------------|
| iOS | 16.0 | 17.0+ | 18.x |
| Xcode | 15.0 | 15.4+ | 16.x |
| Swift | 5.9 | 5.10 | 6.0 |
| Rust | 1.75.0 | 1.80+ | nightly (not required) |
| SQLite | 3.39 | 3.45+ | 3.47 |
| macOS (dev) | 14.0 | 14.5+ | 15.x |
