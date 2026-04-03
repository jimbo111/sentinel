# System Integration (iOS NetworkExtension)

## Overview

This document specifies how the app integrates with iOS's `NetworkExtension` framework to create a local VPN tunnel. The tunnel intercepts all device traffic, passes it through the Rust packet engine for domain extraction, and forwards it transparently.

---

## Architecture: Two Processes

iOS runs the main app and the Network Extension as **separate processes** with separate memory spaces. This is a hard platform constraint, not a design choice.

```
┌─────────────────────────────┐   ┌──────────────────────────────┐
│     Main App Process         │   │  Network Extension Process    │
│                               │   │  (PacketTunnelProvider)       │
│  • SwiftUI views              │   │                                │
│  • VPNManager (control)       │   │  • NEPacketTunnelProvider      │
│  • GRDB (read SQLite)         │   │  • Rust PacketEngine (FFI)     │
│  • APIClient                  │   │  • rusqlite (write SQLite)     │
│                               │   │                                │
│  Memory limit: normal app     │   │  Memory limit: ~6 MB           │
│  Lifecycle: user-controlled   │   │  Lifecycle: system-managed     │
└──────────┬────────────────────┘   └──────────────┬─────────────────┘
           │                                        │
           │        App Group Container             │
           └────────────────┬───────────────────────┘
                            │
                    domains.sqlite
                    UserDefaults (shared)
```

---

## NEPacketTunnelProvider Implementation

### `PacketTunnelProvider.swift`

```swift
import NetworkExtension
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = OSLog(subsystem: "com.yourcompany.domainguard.tunnel",
                            category: "PacketTunnel")

    /// The Rust packet engine instance
    private var rustEngine: RustPacketEngine?

    /// Whether we're actively processing packets
    private var isProcessing = false

    // MARK: - Tunnel Lifecycle

    /// Called by iOS when the user (or system) starts the VPN tunnel.
    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        os_log("Starting tunnel", log: log, type: .info)

        // 1. Configure tunnel network settings
        let settings = createTunnelSettings()

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                os_log("Failed to set tunnel settings: %{public}@",
                       log: self?.log ?? .default, type: .error,
                       error.localizedDescription)
                completionHandler(error)
                return
            }

            // 2. Initialize Rust engine
            do {
                let dbPath = Self.sharedDatabasePath()
                self?.rustEngine = try RustPacketEngine(dbPath: dbPath)
                os_log("Rust engine initialized at %{public}@",
                       log: self?.log ?? .default, type: .info, dbPath)
            } catch {
                os_log("Failed to init Rust engine: %{public}@",
                       log: self?.log ?? .default, type: .error,
                       error.localizedDescription)
                completionHandler(error)
                return
            }

            // 3. Start packet processing loop
            self?.isProcessing = true
            self?.startPacketProcessing()

            // 4. Signal success
            completionHandler(nil)
            os_log("Tunnel started successfully", log: self?.log ?? .default, type: .info)
        }
    }

    /// Called by iOS when the VPN tunnel should stop.
    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        os_log("Stopping tunnel, reason: %d", log: log, type: .info, reason.rawValue)

        isProcessing = false

        // Flush and destroy Rust engine
        rustEngine?.flush()
        rustEngine?.shutdown()
        rustEngine = nil

        completionHandler()
    }

    /// Handle messages from the main app (via NETunnelProviderSession).
    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        // Simple command protocol: first byte is command type
        guard let command = messageData.first else {
            completionHandler?(nil)
            return
        }

        switch command {
        case 0x01: // Flush
            rustEngine?.flush()
            completionHandler?(Data([0x00])) // ACK

        case 0x02: // Get stats
            if let engine = rustEngine {
                let stats = engine.getStats()
                // Encode stats as simple binary (8 bytes per field, 6 fields = 48 bytes)
                var response = Data(capacity: 48)
                withUnsafeBytes(of: stats.packetsProcessed) { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.dnsDomainsFound) { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.sniDomainsFound) { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.packetsSkipped) { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.activeTcpFlows) { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.reassemblyMemoryBytes) { response.append(contentsOf: $0) }
                completionHandler?(response)
            } else {
                completionHandler?(nil)
            }

        default:
            completionHandler?(nil)
        }
    }

    // MARK: - Tunnel Configuration

    /// Create the tunnel network settings.
    ///
    /// This configures the virtual network interface (utun) that iOS creates
    /// for our VPN tunnel. We set it up to intercept ALL traffic.
    private func createTunnelSettings() -> NEPacketTunnelNetworkSettings {
        // Use a private IP for the tunnel interface
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "192.168.1.1")

        // IPv4 settings — route ALL traffic through our tunnel
        let ipv4 = NEIPv4Settings(
            addresses: ["192.168.1.2"],
            subnetMasks: ["255.255.255.0"]
        )
        // includedRoutes = [default route] means ALL IPv4 traffic goes through us
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4

        // IPv6 settings — also route all IPv6 traffic
        let ipv6 = NEIPv6Settings(
            addresses: ["fd00::2"],
            networkPrefixLengths: [64]
        )
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6

        // DNS settings — use the system's DNS servers (NOT DoH/DoT)
        // This is critical: we need DNS queries to go through our tunnel
        // as plaintext UDP so the Rust engine can parse them.
        let dns = NEDNSSettings(servers: ["8.8.8.8", "8.8.4.4"])
        // Do NOT enable DNS-over-HTTPS here. We want plaintext DNS.
        settings.dnsSettings = dns

        // MTU
        settings.mtu = NSNumber(value: 1500)

        return settings
    }

    // MARK: - Packet Processing Loop

    /// Start the continuous packet read/process/write loop.
    ///
    /// This is the core of the VPN tunnel. It reads packets from the
    /// iOS packet flow, passes them through the Rust engine, and writes
    /// them back out (transparent passthrough).
    private func startPacketProcessing() {
        readPacketsFromTunnel()
    }

    /// Read packets from the tunnel, process them, and forward them.
    ///
    /// `packetFlow.readPackets` is async — it calls the completion handler
    /// when packets are available. We recursively call ourselves to create
    /// a continuous loop.
    private func readPacketsFromTunnel() {
        guard isProcessing else { return }

        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isProcessing else { return }

            // Process each packet through the Rust engine
            for (i, packetData) in packets.enumerated() {
                // The Rust engine inspects the packet and extracts domains.
                // It does NOT modify the packet.
                _ = self.rustEngine?.processPacket(packetData)
            }

            // Forward all packets out (transparent passthrough)
            // This sends them to the actual network interface
            self.packetFlow.writePackets(packets, withProtocols: protocols)

            // Continue reading (recursive async loop)
            self.readPacketsFromTunnel()
        }
    }

    // MARK: - Shared Paths

    /// Path to the shared SQLite database in the App Group container.
    static func sharedDatabasePath() -> String {
        let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: AppGroupConfig.groupIdentifier
        )!
        return container.appendingPathComponent("domains.sqlite").path
    }
}
```

---

## Main App: VPN Control (`VPNManager.swift`)

```swift
import NetworkExtension
import Combine
import os.log

/// Manages the VPN tunnel from the main app.
///
/// This class wraps NETunnelProviderManager to provide a clean interface
/// for starting/stopping the VPN and observing its status.
@MainActor
class VPNManager: ObservableObject {

    @Published var status: NEVPNStatus = .disconnected
    @Published var isLoading = false

    private var manager: NETunnelProviderManager?
    private var statusObserver: Any?
    private let log = OSLog(subsystem: "com.yourcompany.domainguard", category: "VPNManager")

    init() {
        loadManager()
        observeStatus()
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    // MARK: - Configuration

    /// Load the existing VPN configuration or create a new one.
    func loadManager() {
        isLoading = true

        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            DispatchQueue.main.async {
                self?.isLoading = false

                if let error = error {
                    os_log("Failed to load VPN config: %{public}@",
                           log: self?.log ?? .default, type: .error,
                           error.localizedDescription)
                    return
                }

                if let existing = managers?.first {
                    self?.manager = existing
                } else {
                    self?.createNewManager()
                }

                self?.status = self?.manager?.connection.status ?? .disconnected
            }
        }
    }

    private func createNewManager() {
        let manager = NETunnelProviderManager()

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.yourcompany.domainguard.tunnel"
        proto.serverAddress = "Local Device" // Display name in Settings
        proto.disconnectOnSleep = false

        manager.protocolConfiguration = proto
        manager.localizedDescription = "DomainGuard"
        manager.isEnabled = true

        self.manager = manager
    }

    /// Save the VPN configuration to system preferences.
    /// This triggers the iOS VPN permission dialog on first run.
    func saveConfiguration() async throws {
        guard let manager = self.manager else {
            throw VPNManagerError.notConfigured
        }

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            manager.saveToPreferences { error in
                if let error = error {
                    cont.resume(throwing: error)
                } else {
                    // Reload after save (Apple recommendation)
                    manager.loadFromPreferences { error in
                        if let error = error {
                            cont.resume(throwing: error)
                        } else {
                            cont.resume()
                        }
                    }
                }
            }
        }
    }

    // MARK: - Connection Control

    /// Start the VPN tunnel.
    func connect() async throws {
        guard let manager = self.manager else {
            throw VPNManagerError.notConfigured
        }

        // Ensure config is saved first
        try await saveConfiguration()

        try manager.connection.startVPNTunnel()
    }

    /// Stop the VPN tunnel.
    func disconnect() {
        manager?.connection.stopVPNTunnel()
    }

    /// Toggle connection state.
    func toggle() async throws {
        switch status {
        case .connected, .connecting:
            disconnect()
        case .disconnected, .invalid:
            try await connect()
        default:
            break
        }
    }

    // MARK: - IPC with Extension

    /// Send a message to the running tunnel extension.
    func sendMessage(_ data: Data) async -> Data? {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            return nil
        }

        return await withCheckedContinuation { cont in
            do {
                try session.sendProviderMessage(data) { response in
                    cont.resume(returning: response)
                }
            } catch {
                cont.resume(returning: nil)
            }
        }
    }

    /// Request the extension to flush domains to SQLite immediately.
    func requestFlush() async {
        _ = await sendMessage(Data([0x01]))
    }

    /// Request engine stats from the extension.
    func requestStats() async -> RustPacketEngine.Stats? {
        guard let data = await sendMessage(Data([0x02])), data.count == 48 else {
            return nil
        }

        return data.withUnsafeBytes { buf in
            RustPacketEngine.Stats(
                packetsProcessed: buf.load(fromByteOffset: 0, as: UInt64.self),
                dnsDomainsFound: buf.load(fromByteOffset: 8, as: UInt64.self),
                sniDomainsFound: buf.load(fromByteOffset: 16, as: UInt64.self),
                packetsSkipped: buf.load(fromByteOffset: 24, as: UInt64.self),
                activeTcpFlows: buf.load(fromByteOffset: 32, as: UInt64.self),
                reassemblyMemoryBytes: buf.load(fromByteOffset: 40, as: UInt64.self)
            )
        }
    }

    // MARK: - Status Observation

    private func observeStatus() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            if let connection = notification.object as? NEVPNConnection {
                self?.status = connection.status
            }
        }
    }
}

// MARK: - Errors

enum VPNManagerError: LocalizedError {
    case notConfigured
    case alreadyConnected

    var errorDescription: String? {
        switch self {
        case .notConfigured: return "VPN manager not configured"
        case .alreadyConnected: return "VPN is already connected"
        }
    }
}
```

---

## Darwin Notifications (Extension → App)

The Network Extension cannot directly push data to the main app. We use Darwin notifications as lightweight "poke" signals.

### Extension side (called from Rust via callback, or from Swift timer):

```swift
// In PacketTunnelProvider
import Darwin

private func notifyAppOfNewDomains() {
    let name = CFNotificationName(
        "com.yourcompany.domainguard.newdomains" as CFString
    )
    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        name,
        nil,
        nil,
        true // deliver immediately
    )
}
```

### App side (`DarwinNotificationListener.swift`):

```swift
import Foundation

/// Listens for Darwin notifications from the Network Extension.
///
/// When the extension has new domain data in SQLite, it posts a
/// Darwin notification. This listener triggers a UI refresh.
class DarwinNotificationListener {

    typealias Handler = () -> Void

    private let name: String
    private var handler: Handler?

    init(name: String) {
        self.name = name
    }

    func startListening(handler: @escaping Handler) {
        self.handler = handler

        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let observer = Unmanaged.passUnretained(self).toOpaque()

        CFNotificationCenterAddObserver(
            center,
            observer,
            { (center, observer, name, object, userInfo) in
                guard let observer = observer else { return }
                let listener = Unmanaged<DarwinNotificationListener>
                    .fromOpaque(observer)
                    .takeUnretainedValue()
                DispatchQueue.main.async {
                    listener.handler?()
                }
            },
            self.name as CFString,
            nil,
            .deliverImmediately
        )
    }

    func stopListening() {
        let center = CFNotificationCenterGetDarwinNotifyCenter()
        let observer = Unmanaged.passUnretained(self).toOpaque()
        CFNotificationCenterRemoveObserver(center, observer, nil, nil)
        handler = nil
    }

    deinit {
        stopListening()
    }
}
```

---

## App Group Configuration (`AppGroupConfig.swift`)

```swift
import Foundation

/// Shared constants between the main app and network extension.
///
/// This file should be included in BOTH targets.
enum AppGroupConfig {
    /// The App Group identifier. Must match the entitlements.
    static let groupIdentifier = "group.com.yourcompany.domainguard"

    /// URL to the App Group container.
    static var containerURL: URL {
        FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: groupIdentifier
        )!
    }

    /// Path to the shared SQLite database.
    static var databasePath: String {
        containerURL.appendingPathComponent("domains.sqlite").path
    }

    /// Shared UserDefaults for cross-process settings.
    static var sharedDefaults: UserDefaults {
        UserDefaults(suiteName: groupIdentifier)!
    }

    /// Darwin notification name for "new domains available".
    static let newDomainsNotification = "com.yourcompany.domainguard.newdomains"
}
```

---

## Apple Developer Requirements

### Entitlements & Provisioning

To use `NEPacketTunnelProvider`, you need:

1. **Apple Developer Account** (paid, $99/year)
2. **Network Extension entitlement** — must be requested from Apple via their form. This is NOT automatic. Submit at: `https://developer.apple.com/contact/request/network-extension/`
3. **App Group capability** — enable in Xcode for both targets
4. **Provisioning profiles** — both the app and extension need separate profiles with the NE entitlement

### Info.plist for Network Extension target

```xml
<key>NSExtension</key>
<dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.networkextension.packet-tunnel</string>
    <key>NSExtensionPrincipalClass</key>
    <string>$(PRODUCT_MODULE_NAME).PacketTunnelProvider</string>
</dict>
```

### Privacy Descriptions (Main App Info.plist)

```xml
<!-- Required: explains why we need VPN permission -->
<key>NSVPNUsageDescription</key>
<string>DomainGuard uses a local VPN to show you which websites and services are accessed by your device. All processing happens on your device — no data is sent to external servers.</string>
```

---

## Packet Flow Optimization

### Avoiding Copies

The `readPackets` API returns `[Data]`. Each `Data` object wraps a packet buffer allocated by iOS. When we pass this to the Rust engine via `processPacket(_ packetData: Data)`, `Data.withUnsafeBytes` gives us a direct pointer — no copy.

The `writePackets` call forwards the same `Data` objects — again, no copy.

The Rust engine receives `&[u8]` (a borrow) and never stores the pointer. Total extra copies per packet: **zero**.

### Batch Processing

`readPackets` returns all queued packets at once (often 10-100 packets per callback). We process them in a batch, then write them all at once. This amortizes the async callback overhead.

### Memory Pressure Handling

```swift
// In PacketTunnelProvider
override func handleMemoryPressure() {
    os_log("Memory pressure received, flushing", log: log, type: .warning)
    rustEngine?.flush()
    // The Rust engine's LRU eviction handles the rest
}
```

The extension should monitor `os_proc_available_memory()` and aggressively flush + evict TCP reassembly buffers if memory drops below 2 MB.
