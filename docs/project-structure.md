# Project Structure

## Repository Layout

```
DomainGuard/
├── DomainGuard.xcodeproj/
│   └── project.pbxproj
│
├── DomainGuard/                          # ── Main App Target ──
│   ├── App/
│   │   ├── DomainGuardApp.swift          # @main entry point (SwiftUI App)
│   │   ├── AppDelegate.swift             # UIKit lifecycle hooks (if needed)
│   │   └── Info.plist
│   │
│   ├── Views/
│   │   ├── MainTabView.swift             # Root tab bar: Domains | Stats | Settings
│   │   ├── Connection/
│   │   │   ├── ConnectionView.swift      # Connect/Disconnect button + status
│   │   │   └── ConnectionViewModel.swift # NETunnelProviderManager wrapper
│   │   ├── Domains/
│   │   │   ├── DomainListView.swift      # Scrollable list of visited domains
│   │   │   ├── DomainRowView.swift       # Single domain row (icon, name, timestamp, count)
│   │   │   ├── DomainDetailView.swift    # Detail: all visits, IP, first/last seen
│   │   │   └── DomainListViewModel.swift # SQLite queries via GRDB, reactive updates
│   │   ├── Stats/
│   │   │   ├── StatsView.swift           # Charts: domains/hour, top domains, categories
│   │   │   └── StatsViewModel.swift
│   │   └── Settings/
│   │       ├── SettingsView.swift         # Preferences, whitelist/blacklist, export
│   │       └── SettingsViewModel.swift
│   │
│   ├── Services/
│   │   ├── VPNManager.swift              # NETunnelProviderManager start/stop/status
│   │   ├── DatabaseReader.swift          # GRDB read-only access to shared SQLite
│   │   ├── DarwinNotificationListener.swift  # Listen for "new domains" from extension
│   │   └── APIClient.swift              # Cloud backend HTTP client (auth, config)
│   │
│   ├── Models/
│   │   ├── DomainRecord.swift            # Domain name, first seen, last seen, visit count
│   │   ├── ConnectionStatus.swift        # enum: disconnected, connecting, connected, error
│   │   └── UserSettings.swift            # Codable settings model
│   │
│   ├── Utilities/
│   │   ├── AppGroupConstants.swift       # App Group ID, shared paths
│   │   └── DateFormatters.swift
│   │
│   ├── Resources/
│   │   ├── Assets.xcassets/
│   │   └── Localizable.strings
│   │
│   └── DomainGuard.entitlements          # App Groups, Network Extension (app side)
│
├── PacketTunnelExtension/                # ── Network Extension Target ──
│   ├── PacketTunnelProvider.swift         # NEPacketTunnelProvider subclass
│   ├── PacketTunnelProvider+PacketFlow.swift  # readPackets/writePackets loop
│   ├── RustBridge.swift                  # Swift wrappers around C FFI functions
│   ├── Bridge/
│   │   └── packet_engine.h               # Auto-generated C header (cbindgen output)
│   ├── PacketTunnelExtension-Bridging-Header.h  # #import "Bridge/packet_engine.h"
│   ├── Info.plist                        # NSExtension config
│   └── PacketTunnelExtension.entitlements # App Groups, Network Extension (extension side)
│
├── Frameworks/                           # ── Prebuilt Libraries ──
│   └── libpacket_engine.a                # Compiled Rust static library (aarch64)
│
├── rust/                                 # ── Rust Workspace ──
│   └── packet_engine/
│       ├── Cargo.toml
│       ├── Cargo.lock
│       ├── build.rs                      # cbindgen header generation
│       ├── cbindgen.toml                 # cbindgen configuration
│       ├── src/
│       │   ├── lib.rs                    # FFI entry points (extern "C" functions)
│       │   ├── engine.rs                 # PacketEngine struct: init, process, shutdown
│       │   ├── ip.rs                     # IPv4/IPv6 header parser
│       │   ├── dns.rs                    # DNS query + response parser (UDP/53)
│       │   ├── tls.rs                    # TLS ClientHello / SNI extractor + ECH detection
│       │   ├── tcp_reassembly.rs         # Bounded TCP segment reassembly buffer
│       │   ├── dns_filter.rs             # Active ECH downgrade: HTTPS RR ech= stripping
│       │   ├── ech_correlator.rs         # DNS/IP correlation for passive ECH fallback
│       │   ├── domain.rs                 # DomainRecord struct, dedup, normalization
│       │   ├── storage.rs                # SQLite writer (rusqlite, batch inserts)
│       │   ├── errors.rs                 # Error enum (thiserror)
│       │   └── constants.rs              # Buffer sizes, timeouts, port numbers
│       └── tests/
│           ├── dns_test.rs               # Unit tests with captured DNS packets
│           ├── tls_test.rs               # Unit tests with captured TLS ClientHello
│           ├── tcp_reassembly_test.rs    # Reassembly edge cases
│           ├── integration_test.rs       # Full pipeline: raw bytes → SQLite records
│           └── fixtures/
│               ├── dns_query_google.bin  # Raw DNS query for google.com
│               ├── tls_hello_amazon.bin  # Raw TLS ClientHello for amazon.com
│               └── tcp_fragmented_sni.bin # Multi-segment TLS handshake
│
├── Shared/                               # ── Code shared between targets ──
│   └── AppGroupConfig.swift              # App Group ID constant, shared file paths
│
├── docs/                                 # ── Documentation (these .md files) ──
│   ├── architecture.md
│   ├── tech-stack.md
│   ├── project-structure.md              # (this file)
│   ├── local-packet-engine.md
│   ├── cross-platform-bindings.md
│   ├── system-integration.md
│   ├── data-storage.md
│   ├── design-elements.md
│   ├── backend.md
│   ├── ech-fallback.md
│   └── implementation-phases.md
│
├── scripts/
│   ├── build-rust.sh                     # Build Rust for device/simulator
│   ├── build-universal.sh               # Build fat binary (device + simulator)
│   └── generate-test-fixtures.py         # Generate test packet captures
│
├── .github/
│   └── workflows/
│       └── ci.yml                        # GitHub Actions CI pipeline
│
├── .gitignore
└── README.md
```

---

## Xcode Target Configuration

### Target 1: `DomainGuard` (Main App)

| Setting | Value |
|---------|-------|
| Bundle ID | `com.yourcompany.domainguard` |
| Deployment Target | iOS 16.0 |
| Frameworks | `NetworkExtension.framework` |
| App Groups | `group.com.yourcompany.domainguard` |
| Capabilities | Network Extensions (Packet Tunnel), App Groups |
| Swift Packages | GRDB.swift (via SPM) |

### Target 2: `PacketTunnelExtension` (Network Extension)

| Setting | Value |
|---------|-------|
| Bundle ID | `com.yourcompany.domainguard.tunnel` |
| Deployment Target | iOS 16.0 |
| Frameworks | `NetworkExtension.framework` |
| App Groups | `group.com.yourcompany.domainguard` |
| Capabilities | Network Extensions (Packet Tunnel), App Groups |
| Linked Libraries | `libpacket_engine.a` (from `Frameworks/`) |
| Bridging Header | `PacketTunnelExtension-Bridging-Header.h` |
| Other Linker Flags | `-lpacket_engine`, `-lsqlite3`, `-lz`, `-lresolv` |
| Library Search Paths | `$(SRCROOT)/Frameworks` |

**Linker flags explained**:
- `-lpacket_engine` — The Rust static library
- `-lsqlite3` — System SQLite (rusqlite's bundled SQLite may still need this for iOS compatibility)
- `-lz` — zlib (dependency of some Rust crates)
- `-lresolv` — DNS resolver (required by iOS linker for network code)

### NSExtension Configuration (Info.plist)

```xml
<key>NSExtension</key>
<dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.networkextension.packet-tunnel</string>
    <key>NSExtensionPrincipalClass</key>
    <string>$(PRODUCT_MODULE_NAME).PacketTunnelProvider</string>
</dict>
```

---

## Entitlements

### DomainGuard.entitlements (Main App)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <key>com.apple.developer.networking.networkextension</key>
    <array>
        <string>packet-tunnel-provider</string>
    </array>
    <key>com.apple.security.application-groups</key>
    <array>
        <string>group.com.yourcompany.domainguard</string>
    </array>
</dict>
</plist>
```

### PacketTunnelExtension.entitlements

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <key>com.apple.developer.networking.networkextension</key>
    <array>
        <string>packet-tunnel-provider</string>
    </array>
    <key>com.apple.security.application-groups</key>
    <array>
        <string>group.com.yourcompany.domainguard</string>
    </array>
</dict>
</plist>
```

---

## Build Scripts

### `scripts/build-rust.sh`

```bash
#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RUST_DIR="$PROJECT_ROOT/rust/packet_engine"
FRAMEWORKS_DIR="$PROJECT_ROOT/Frameworks"
BRIDGE_DIR="$PROJECT_ROOT/PacketTunnelExtension/Bridge"

TARGET="${1:-aarch64-apple-ios}"  # Default: device build

echo "Building Rust packet_engine for target: $TARGET"
cd "$RUST_DIR"
cargo build --target "$TARGET" --release

echo "Copying artifacts..."
mkdir -p "$FRAMEWORKS_DIR" "$BRIDGE_DIR"
cp "target/$TARGET/release/libpacket_engine.a" "$FRAMEWORKS_DIR/"
cp "target/packet_engine.h" "$BRIDGE_DIR/"

echo "Done. Library: $FRAMEWORKS_DIR/libpacket_engine.a"
echo "Header:  $BRIDGE_DIR/packet_engine.h"
```

### `scripts/build-universal.sh`

```bash
#!/bin/bash
set -euo pipefail

# Build for both device and simulator, then create universal binary
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RUST_DIR="$PROJECT_ROOT/rust/packet_engine"

cd "$RUST_DIR"
cargo build --target aarch64-apple-ios --release
cargo build --target aarch64-apple-ios-sim --release

# Create XCFramework-compatible structure
mkdir -p "$PROJECT_ROOT/Frameworks/ios-arm64"
mkdir -p "$PROJECT_ROOT/Frameworks/ios-arm64-simulator"

cp "target/aarch64-apple-ios/release/libpacket_engine.a" \
   "$PROJECT_ROOT/Frameworks/ios-arm64/"
cp "target/aarch64-apple-ios-sim/release/libpacket_engine.a" \
   "$PROJECT_ROOT/Frameworks/ios-arm64-simulator/"

echo "Built for device and simulator."
```

---

## .gitignore Additions

```gitignore
# Rust build artifacts
rust/packet_engine/target/

# Compiled library (rebuilt from source)
Frameworks/libpacket_engine.a

# Generated header (rebuilt from source)
PacketTunnelExtension/Bridge/packet_engine.h

# Xcode
*.xcuserdata
DerivedData/
```
