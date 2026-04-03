import NetworkExtension
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = OSLog(subsystem: "com.jimmykim.sentinel.tunnel", category: "PacketTunnel")

    /// Single serial queue that protects ALL mutable state in this class.
    private let queue = DispatchQueue(label: "com.jimmykim.sentinel.tunnel.state")

    /// Serializes ALL calls into the RustPacketEngine instance.
    private let engineQueue = DispatchQueue(label: "com.jimmykim.sentinel.tunnel.engine")

    // -- Protected by `queue` --
    private var rustEngine: RustPacketEngine?
    private var dnsForwarder: DNSForwarder?
    private var isProcessing = false
    private var isStopping = false
    private var lastNotificationTime: CFAbsoluteTime = 0

    // MARK: - Tunnel Lifecycle

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        #if DEBUG
        NSLog("[Ring Tunnel] startTunnel called")
        #endif
        os_log("Starting tunnel", log: log, type: .default)

        // Monitor memory pressure (NE has ~15MB limit)
        setupMemoryPressureMonitor()

        let statusPath = AppGroupConfig.containerURL.appendingPathComponent("tunnel_status.txt").path
        try? FileManager.default.removeItem(atPath: statusPath)

        queue.sync { isStopping = false }

        let settings = createTunnelSettings()

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }

            let stopping = self.queue.sync { self.isStopping }
            if stopping {
                os_log("startTunnel callback fired after stopTunnel; aborting.", log: self.log, type: .default)
                completionHandler(NEVPNError(.configurationDisabled))
                return
            }

            if let error = error {
                os_log("Failed to set tunnel settings: %{public}@", log: self.log, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }

            do {
                let dbPath = AppGroupConfig.databasePath
                self.writeDebugStatus("init_start: dbPath=\(dbPath)")

                let engine = try RustPacketEngine(dbPath: dbPath)
                self.writeDebugStatus("engine_ok: Rust engine initialized")

                let dbExists = FileManager.default.fileExists(atPath: dbPath)
                self.writeDebugStatus("db_exists=\(dbExists) at \(dbPath)")

                let forwarder = DNSForwarder(
                    tunnelProvider: self,
                    packetFlow: self.packetFlow,
                    log: self.log
                ) { [weak self] msg in
                    self?.writeDebugStatus(msg)
                }

                let filterNoise = AppGroupConfig.sharedDefaults.object(forKey: "filterNoise") as? Bool ?? true
                engine.setNoiseFilter(enabled: filterNoise)

                // Load cached threat feeds from App Group container.
                self.loadCachedThreatFeeds(engine: engine)

                // Sync allowlist from UserDefaults into the Rust engine.
                self.syncAllowlist(engine: engine)

                self.queue.sync {
                    self.rustEngine = engine
                    self.dnsForwarder = forwarder
                    self.isProcessing = true
                }

                self.startPacketProcessing()
                completionHandler(nil)
                self.writeDebugStatus("tunnel_started: processing packets")
                #if DEBUG
                NSLog("[Ring Tunnel] Tunnel started successfully, processing packets")
                #endif
            } catch {
                self.writeDebugStatus("engine_FAILED: \(error.localizedDescription)")
                os_log("Failed to init Rust engine: %{public}@", log: self.log, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Stopping tunnel, reason: %d", log: log, type: .default, reason.rawValue)

        queue.sync {
            isStopping = true
            isProcessing = false
        }

        let (engine, forwarder) = queue.sync { () -> (RustPacketEngine?, DNSForwarder?) in
            let e = rustEngine
            let f = dnsForwarder
            dnsForwarder = nil
            rustEngine = nil
            return (e, f)
        }

        forwarder?.shutdown()
        engineQueue.sync { engine?.flush() }
        notifyAppOfNewDomains()
        engineQueue.sync { engine?.shutdown() }

        os_log("Tunnel stopped", log: log, type: .default)
        completionHandler()
    }

    // MARK: - Sleep/Wake (iOS 17+ calls every ~6 seconds)

    override func sleep(completionHandler: @escaping () -> Void) {
        // Must be cheap — iOS 17+ calls this every 6 seconds.
        // Just call the handler immediately; DNS forwarder stays alive.
        completionHandler()
    }

    override func wake() {
        // Re-check session health after wake. Network path may have changed.
        queue.async { [weak self] in
            self?.dnsForwarder?.checkSessionsAfterWake()
        }
    }

    private var memoryPressureSource: DispatchSourceMemoryPressure?

    private func setupMemoryPressureMonitor() {
        let source = DispatchSource.makeMemoryPressureSource(eventMask: [.warning, .critical], queue: queue)
        source.setEventHandler { [weak self] in
            guard let self = self else { return }
            let level = source.data.contains(.critical) ? "CRITICAL" : "WARNING"
            os_log("Memory pressure %{public}@ — flushing engine buffers", log: self.log, type: .error, level)
            self.writeDebugStatus("MEMORY_\(level): flushing buffers")
            let engine = self.rustEngine
            self.engineQueue.async { engine?.flush() }
        }
        source.resume()
        memoryPressureSource = source
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        guard let command = messageData.first else {
            completionHandler?(nil)
            return
        }

        switch command {
        case 0x01:
            let engine = queue.sync { rustEngine }
            engineQueue.sync { engine?.flush() }
            notifyAppOfNewDomains()
            completionHandler?(Data([0x00]))
        case 0x02:
            let engine = queue.sync { rustEngine }
            if let engine = engine {
                let stats = engineQueue.sync { engine.getStats() }
                let fwd = self.queue.sync { self.dnsForwarder }
                let dnsStats = fwd.map { "sent=\($0.queriesSent) ok=\($0.responsesReceived) timeout=\($0.queriesTimedOut) drop=\($0.queriesDropped) reconn=\($0.sessionsRecreated)" } ?? "n/a"
                writeDebugStatus("ipc_stats: pkts=\(stats.packetsProcessed) dns=\(stats.dnsDomainsFound) sni=\(stats.sniDomainsFound) \(dnsStats)")
                var response = Data(capacity: 80)
                withUnsafeBytes(of: stats.packetsProcessed)       { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.dnsDomainsFound)        { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.sniDomainsFound)        { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.packetsSkipped)         { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.activeTcpFlows)         { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.reassemblyMemoryBytes)  { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.echConfigsStripped)     { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.echConnectionsDetected) { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.echResolvedViaDns)      { response.append(contentsOf: $0) }
                withUnsafeBytes(of: stats.echUnresolved)          { response.append(contentsOf: $0) }
                completionHandler?(response)
            } else {
                completionHandler?(nil)
            }
        case 0x03:
            if messageData.count >= 2 {
                let engine = queue.sync { rustEngine }
                engineQueue.sync { engine?.setEchDowngrade(enabled: messageData[1] == 0x01) }
            }
            completionHandler?(Data([0x00]))
        case 0x04:
            if messageData.count >= 2 {
                let engine = queue.sync { rustEngine }
                engineQueue.sync { engine?.setNoiseFilter(enabled: messageData[1] == 0x01) }
            }
            completionHandler?(Data([0x00]))
        default:
            completionHandler?(nil)
        }
    }

    // MARK: - Tunnel Configuration

    /// Virtual DNS server IP — exists only within the tunnel.
    /// Apps send DNS queries to this IP (via dnsSettings), the tunnel
    /// captures them (via includedRoutes), and the forwarder resolves
    /// them via the REAL DNS server (8.8.8.8) which is NOT routed
    /// through the tunnel, breaking the routing loop.
    static let virtualDNSIP = "198.18.0.1"

    private func createTunnelSettings() -> NEPacketTunnelNetworkSettings {
        // Use 198.18.0.0/15 range (RFC 2544 benchmarking, never routable) to avoid
        // conflicts with common LAN gateways like 192.168.1.1.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.18.0.2")

        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.3"], subnetMasks: ["255.255.255.0"])
        let dnsRoute = NEIPv4Route(destinationAddress: Self.virtualDNSIP, subnetMask: "255.255.255.255")
        ipv4.includedRoutes = [dnsRoute]
        settings.ipv4Settings = ipv4

        // Tell iOS to send all DNS queries to our virtual IP.
        // The queries arrive at the tunnel, we extract domains,
        // then forward to Google DNS on the physical interface.
        let dns = NEDNSSettings(servers: [Self.virtualDNSIP])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        settings.mtu = NSNumber(value: 1500)

        return settings
    }

    // MARK: - Debug Status

    private static let debugDateFormatter = ISO8601DateFormatter()

    private static let maxLogBytes = 100 * 1024  // 100 KB max log size

    private func writeDebugStatus(_ message: String) {
        let statusPath = AppGroupConfig.containerURL.appendingPathComponent("tunnel_status.txt").path
        let timestamp = Self.debugDateFormatter.string(from: Date())
        let line = "[\(timestamp)] \(message)\n"
        if FileManager.default.fileExists(atPath: statusPath) {
            if let handle = try? FileHandle(forUpdating: URL(fileURLWithPath: statusPath)) {
                // Rotate: if file exceeds 100KB, keep last 50KB
                let fileSize = handle.seekToEndOfFile()
                if fileSize > Self.maxLogBytes {
                    let keepFrom = fileSize - UInt64(Self.maxLogBytes / 2)
                    handle.seek(toFileOffset: keepFrom)
                    let tail = handle.readDataToEndOfFile()
                    handle.seek(toFileOffset: 0)
                    handle.write(tail)
                    handle.truncateFile(atOffset: UInt64(tail.count))
                    handle.seekToEndOfFile()
                }
                handle.write(Data(line.utf8))
                handle.closeFile()
            }
        } else {
            try? line.write(toFile: statusPath, atomically: true, encoding: .utf8)
        }
    }

    // MARK: - Darwin Notifications

    private func notifyAppOfNewDomains() {
        let name = CFNotificationName(AppGroupConfig.newDomainsNotification as CFString)
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            name, nil, nil, true
        )
    }

    private func maybeNotifyApp() {
        let now = CFAbsoluteTimeGetCurrent()
        if now - lastNotificationTime >= 1.0 {
            lastNotificationTime = now
            notifyAppOfNewDomains()
        }
    }

    // MARK: - Threat Feed Loading

    /// Load cached threat feed files from the App Group container into the
    /// Rust engine.  Called once during `startTunnel`, on the same thread
    /// before the packet loop starts (no race condition).
    private func loadCachedThreatFeeds(engine: RustPacketEngine) {
        let container = AppGroupConfig.containerURL
        let feeds: [(filename: String, name: String)] = [
            ("hagezi-pro.txt", "hagezi-pro"),
            ("urlhaus-hosts.txt", "urlhaus-malware"),
        ]
        for feed in feeds {
            let url = container.appendingPathComponent(feed.filename)
            guard let data = try? String(contentsOf: url, encoding: .utf8) else {
                writeDebugStatus("feed_miss: \(feed.filename) not cached yet")
                continue
            }
            let ok = engine.loadThreatFeed(data: data, feedName: feed.name)
            writeDebugStatus("feed_loaded: \(feed.name) ok=\(ok) size=\(data.count)")
        }
    }

    /// Sync the allowlist from shared UserDefaults into the Rust engine's
    /// in-memory allowlist.
    private func syncAllowlist(engine: RustPacketEngine) {
        let list = AppGroupConfig.sharedDefaults.stringArray(forKey: "sentinel_allowlist") ?? []
        for domain in list {
            _ = engine.addAllowlistDomain(domain)
        }
        writeDebugStatus("allowlist_synced: \(list.count) domains")
    }

    /// Post a Darwin notification so the main app's threat dashboard refreshes.
    private func notifyAppOfThreatAlert() {
        let name = CFNotificationName(AppGroupConfig.threatAlertNotification as CFString)
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            name, nil, nil, true
        )
    }

    // MARK: - Packet Processing

    private var totalPacketsReceived: Int = 0

    private func startPacketProcessing() {
        readPacketsFromTunnel()
    }

    private func readPacketsFromTunnel() {
        let processing = queue.sync { isProcessing }
        guard processing else { return }

        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }

            let (engine, forwarder, active) = self.queue.sync {
                (self.rustEngine, self.dnsForwarder, self.isProcessing)
            }
            guard active else { return }

            let totalSoFar = self.queue.sync { () -> Int in
                self.totalPacketsReceived += packets.count
                return self.totalPacketsReceived
            }
            if totalSoFar <= packets.count || totalSoFar % 100 < packets.count {
                self.writeDebugStatus("packets_received: batch=\(packets.count) total=\(totalSoFar)")
            }

            let engineQueue = self.engineQueue
            for (i, packetData) in packets.enumerated() {
                var outPacket = packetData
                if let engine = engine {
                    let result = engineQueue.sync { engine.processPacket(packetData) }
                    switch result {
                    case .replace(let modified):
                        outPacket = modified
                    case .block(let sinkhole):
                        // DNS sinkhole: write the 0.0.0.0 response back to the
                        // tunnel so the client gets an immediate failure instead
                        // of a 5-second timeout.  Do NOT forward to the real DNS.
                        self.packetFlow.writePackets([sinkhole], withProtocols: [protocols[i]])
                        self.queue.async { self.notifyAppOfThreatAlert() }
                        continue
                    case .forward:
                        break
                    }
                }

                forwarder?.forwardDNSPacket(outPacket, protocolFamily: protocols[i]) { responsePacket in
                    guard let engine = engine else { return responsePacket }
                    return engineQueue.sync {
                        let result = engine.processPacket(responsePacket)
                        switch result {
                        case .replace(let modified):
                            return modified
                        case .block(let sinkhole):
                            return sinkhole
                        case .forward:
                            return responsePacket
                        }
                    }
                }
            }

            self.queue.async { self.maybeNotifyApp() }
            self.readPacketsFromTunnel()
        }
    }
}

// MARK: - DNS Forwarder (NWUDPSession-based, bypasses tunnel)

class DNSForwarder: NSObject {
    private let packetFlow: NEPacketTunnelFlow
    private let log: OSLog
    private let debugLog: (String) -> Void
    private weak var tunnelProvider: NEPacketTunnelProvider?

    private let queue: DispatchQueue

    private var session: NWUDPSession?
    private var isSessionReady = false
    private var secondarySession: NWUDPSession?
    private var isSecondarySessionReady = false
    private var primaryObserverRemoved = false
    private var secondaryObserverRemoved = false
    private var pendingQueries: [UInt16: PendingQuery] = [:]
    private var queuedSends: [(Data, UInt16)] = []

    private static let maxPendingQueries = 128
    private static let queryTimeoutSeconds: Double = 5.0
    private static let minSendIntervalMs: Double = 50.0  // 20 queries/sec max — prevents NWUDPSession read handler death
    private static let stallDetectionSeconds: Double = 5.0  // Faster recovery

    private var isShutdown = false
    private var lastSendTime: CFAbsoluteTime = 0
    private var sendDelayCounter: Int = 0
    private var lastResponseTime: CFAbsoluteTime = 0
    private(set) var sessionsRecreated: Int = 0

    // DNS reliability metrics
    private(set) var queriesSent: Int = 0
    private(set) var responsesReceived: Int = 0
    private(set) var queriesTimedOut: Int = 0
    private(set) var queriesDropped: Int = 0

    private struct PendingQuery {
        let originalPacket: Data
        let ipHeaderLen: Int
        let srcPort: UInt16
        let protocolFamily: NSNumber
        let processResponse: (Data) -> Data
        var deadline: DispatchWorkItem
    }

    /// Placeholder for deferred timeout — used when query hasn't been sent yet.
    private class PendingQueryTimeoutHolder {
        let workItem = DispatchWorkItem { }
    }

    init(tunnelProvider: NEPacketTunnelProvider, packetFlow: NEPacketTunnelFlow, log: OSLog, debugLog: @escaping (String) -> Void) {
        self.tunnelProvider = tunnelProvider
        self.packetFlow = packetFlow
        self.log = log
        self.debugLog = debugLog
        self.queue = DispatchQueue(label: "com.jimmykim.sentinel.dnsforwarder")
        super.init()
        os_log("DNS forwarder initialized (NWUDPSession)", log: log, type: .default)
    }

    func shutdown() {
        queue.sync {
            isShutdown = true
            for (_, pending) in pendingQueries {
                pending.deadline.cancel()
            }
            pendingQueries.removeAll()
            queuedSends.removeAll()
            if let session = session {
                session.removeObserver(self, forKeyPath: "state")
                session.cancel()
            }
            session = nil
            isSessionReady = false
            if let sec = secondarySession {
                sec.removeObserver(self, forKeyPath: "state")
                sec.cancel()
            }
            secondarySession = nil
            isSecondarySessionReady = false
        }
        os_log("DNS forwarder shut down", log: log, type: .default)
    }

    // MARK: - Public

    func forwardDNSPacket(_ packet: Data, protocolFamily: NSNumber, processResponse: @escaping (Data) -> Data) {
        guard packet.count >= 28 else { return }
        let version = packet[0] >> 4
        guard version == 4 else { return }

        let ipHeaderLen = Int(packet[0] & 0x0F) * 4
        guard ipHeaderLen >= 20, packet.count >= ipHeaderLen + 8 else { return }
        guard packet[9] == 17 else { return }

        let udpOffset = ipHeaderLen
        let dstPort = UInt16(packet[udpOffset + 2]) << 8 | UInt16(packet[udpOffset + 3])
        guard dstPort == 53 else { return }

        let srcPort = UInt16(packet[udpOffset]) << 8 | UInt16(packet[udpOffset + 1])
        let dnsPayload = packet[(udpOffset + 8)...]
        guard dnsPayload.count >= 12 else { return }

        let txnID = UInt16(dnsPayload[dnsPayload.startIndex]) << 8
                  | UInt16(dnsPayload[dnsPayload.startIndex + 1])

        #if DEBUG
        if let domain = Self.extractDomainFromDNS(dnsPayload) {
            NSLog("[Ring DNS] Forwarding txn 0x%04x: %@", txnID, domain)
        }
        #endif

        queue.async { [weak self] in
            self?.sendQuery(
                packet: packet,
                ipHeaderLen: ipHeaderLen,
                srcPort: srcPort,
                dnsPayload: Data(dnsPayload),
                txnID: txnID,
                protocolFamily: protocolFamily,
                processResponse: processResponse
            )
        }
    }

    // MARK: - Session Management

    private func ensureSession() {
        // Reuse existing primary session if it's still viable
        if let existing = session {
            let state = existing.state
            if state != .failed && state != .cancelled && state != .invalid {
                // Primary is alive — also ensure secondary is alive
                ensureSecondarySession()
                return
            }
            // Dead session — tear it down
            existing.removeObserver(self, forKeyPath: "state")
            existing.cancel()
            session = nil
            isSessionReady = false
        }

        guard let provider = tunnelProvider else {
            debugLog("dns_ERR: tunnelProvider is nil, cannot create UDP session")
            return
        }

        let endpoint = NWHostEndpoint(hostname: "8.8.8.8", port: "53")
        let newSession = provider.createUDPSession(to: endpoint, from: nil)
        session = newSession
        isSessionReady = false
        primaryObserverRemoved = false

        debugLog("dns_session: creating UDP session to 8.8.8.8:53, pending=\(pendingQueries.count)")

        // Observe state changes via KVO
        newSession.addObserver(self, forKeyPath: "state", options: [.new], context: nil)

        // Set read handler ONCE — it fires continuously for all incoming datagrams
        newSession.setReadHandler({ [weak self] datagrams, error in
            guard let self = self else { return }
            self.queue.async {
                if let error = error {
                    os_log("DNS receive error (primary): %{public}@", log: self.log, type: .error, error.localizedDescription)
                    self.debugLog("dns_recv_err: \(error.localizedDescription) pending=\(self.pendingQueries.count)")
                    // Do NOT return early — continue processing any datagrams we did receive
                }

                guard let datagrams = datagrams else { return }

                for data in datagrams {
                    guard data.count >= 2 else { continue }
                    let txnID = UInt16(data[0]) << 8 | UInt16(data[1])
                    self.handleResponse(data: data, txnID: txnID)
                }
            }
        }, maxDatagrams: 64)

        // Also bring up secondary session alongside primary
        ensureSecondarySession()
    }

    private func ensureSecondarySession() {
        // Reuse existing secondary session if it's still viable
        if let existing = secondarySession {
            let state = existing.state
            if state != .failed && state != .cancelled && state != .invalid {
                return
            }
            existing.removeObserver(self, forKeyPath: "state")
            existing.cancel()
            secondarySession = nil
            isSecondarySessionReady = false
        }

        guard let provider = tunnelProvider else { return }

        let endpoint = NWHostEndpoint(hostname: "1.1.1.1", port: "53")
        let newSecSession = provider.createUDPSession(to: endpoint, from: nil)
        secondarySession = newSecSession
        isSecondarySessionReady = false
        secondaryObserverRemoved = false

        debugLog("dns_session: creating secondary UDP session to 1.1.1.1:53")

        newSecSession.addObserver(self, forKeyPath: "state", options: [.new], context: nil)

        // Secondary read handler — responses from 1.1.1.1 are matched by txnID
        // exactly like primary responses, since pendingQueries is shared.
        newSecSession.setReadHandler({ [weak self] datagrams, error in
            guard let self = self else { return }
            self.queue.async {
                if let error = error {
                    os_log("DNS receive error (secondary): %{public}@", log: self.log, type: .error, error.localizedDescription)
                    self.debugLog("dns_recv_err_sec: \(error.localizedDescription) pending=\(self.pendingQueries.count)")
                }

                guard let datagrams = datagrams else { return }

                for data in datagrams {
                    guard data.count >= 2 else { continue }
                    let txnID = UInt16(data[0]) << 8 | UInt16(data[1])
                    self.handleResponse(data: data, txnID: txnID)
                }
            }
        }, maxDatagrams: 64)
    }

    // KVO observer for session state — handles both primary and secondary sessions
    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey: Any]?, context: UnsafeMutableRawPointer?) {
        guard keyPath == "state", let observedSession = object as? NWUDPSession else {
            super.observeValue(forKeyPath: keyPath, of: object, change: change, context: context)
            return
        }

        queue.async { [weak self] in
            guard let self = self else { return }

            let isPrimary = self.session === observedSession
            let label = isPrimary ? "primary(8.8.8.8)" : "secondary(1.1.1.1)"

            switch observedSession.state {
            case .ready:
                if isPrimary {
                    os_log("DNS UDP session ready (primary)", log: self.log, type: .default)
                    self.isSessionReady = true
                    self.debugLog("dns_state: \(label) READY, flushing \(self.queuedSends.count) queued sends, pending=\(self.pendingQueries.count)")
                    self.flushQueuedSends()
                } else {
                    os_log("DNS UDP session ready (secondary)", log: self.log, type: .default)
                    self.isSecondarySessionReady = true
                    self.debugLog("dns_state: \(label) READY, flushing \(self.queuedSends.count) queued sends, pending=\(self.pendingQueries.count)")
                    // If the primary already flushed, queuedSends will be empty — safe no-op.
                    // If secondary beats primary to ready, it flushes the burst and primary
                    // becomes available for subsequent queries.
                    self.flushQueuedSends()
                }
            case .failed:
                if isPrimary {
                    os_log("DNS UDP session failed (primary)", log: self.log, type: .error)
                    self.debugLog("dns_state: \(label) FAILED, draining \(self.pendingQueries.count) queries + \(self.queuedSends.count) queued")
                    self.isSessionReady = false
                    self.failAllPendingQueries()
                    self.queuedSends.removeAll()
                    if !self.primaryObserverRemoved {
                        observedSession.removeObserver(self, forKeyPath: "state")
                        self.primaryObserverRemoved = true
                    }
                    observedSession.cancel()
                    self.session = nil
                } else {
                    os_log("DNS UDP session failed (secondary)", log: self.log, type: .error)
                    self.debugLog("dns_state: \(label) FAILED")
                    self.isSecondarySessionReady = false
                    if !self.secondaryObserverRemoved {
                        observedSession.removeObserver(self, forKeyPath: "state")
                        self.secondaryObserverRemoved = true
                    }
                    observedSession.cancel()
                    if self.secondarySession === observedSession {
                        self.secondarySession = nil
                    }
                }
            case .cancelled:
                if isPrimary {
                    os_log("DNS UDP session cancelled (primary)", log: self.log, type: .debug)
                    self.debugLog("dns_state: \(label) cancelled")
                    self.isSessionReady = false
                    if !self.primaryObserverRemoved {
                        observedSession.removeObserver(self, forKeyPath: "state")
                        self.primaryObserverRemoved = true
                    }
                    if self.session === observedSession {
                        self.session = nil
                    }
                } else {
                    os_log("DNS UDP session cancelled (secondary)", log: self.log, type: .debug)
                    self.debugLog("dns_state: \(label) cancelled")
                    self.isSecondarySessionReady = false
                    if !self.secondaryObserverRemoved {
                        observedSession.removeObserver(self, forKeyPath: "state")
                        self.secondaryObserverRemoved = true
                    }
                    if self.secondarySession === observedSession {
                        self.secondarySession = nil
                    }
                }
            case .preparing:
                self.debugLog("dns_state: \(label) preparing")
            case .invalid:
                self.debugLog("dns_state: \(label) invalid")
                if isPrimary {
                    self.isSessionReady = false
                } else {
                    self.isSecondarySessionReady = false
                }
            @unknown default:
                break
            }
        }
    }

    private func flushQueuedSends() {
        // Reset the rate-limit counter so burst sends after reconnect are not
        // artificially delayed by a counter inflated during the previous session.
        sendDelayCounter = 0

        // Either primary or secondary becoming ready can trigger a flush.
        // If neither is ready yet, wait.
        guard isSessionReady || isSecondarySessionReady else { return }

        let sends = queuedSends
        queuedSends.removeAll()
        guard !sends.isEmpty else { return }

        // Capture both sessions now so each asyncAfter closure routes to the
        // correct server even if session state changes later.
        let primarySession = isSessionReady ? session : nil
        let secondarySession = isSecondarySessionReady ? self.secondarySession : nil

        debugLog("dns_flush: staggering \(sends.count) startup-burst queries at \(Self.minSendIntervalMs)ms intervals, primary=\(primarySession != nil) secondary=\(secondarySession != nil)")

        // Stagger sends at 25ms intervals to give DNS servers breathing room.
        // During the startup burst, alternate between primary (8.8.8.8) and
        // secondary (1.1.1.1) so neither server is overwhelmed.
        // Odd-indexed queries go to primary, even-indexed to secondary.
        // If only one session is ready, all queries go to that session.
        for (index, (payload, txnID)) in sends.enumerated() {
            let delay = Double(index) * Self.minSendIntervalMs / 1000.0

            // Determine target session at dispatch time (captured above, not at fire time)
            let targetSession: NWUDPSession?
            if let pri = primarySession, let sec = secondarySession {
                targetSession = (index % 2 == 1) ? pri : sec
            } else {
                targetSession = primarySession ?? secondarySession
            }

            guard let target = targetSession else {
                debugLog("dns_flush: no session available for txn 0x\(String(txnID, radix: 16)), dropping")
                continue
            }

            queue.asyncAfter(deadline: .now() + delay) { [weak self] in
                guard let self = self, !self.isShutdown else { return }

                // Set up a real timeout for this queued query (replaces placeholder)
                let timeoutWork = DispatchWorkItem { [weak self] in
                    guard let self = self else { return }
                    if let pending = self.pendingQueries.removeValue(forKey: txnID) {
                        pending.deadline.cancel()
                        self.queriesTimedOut += 1
                        self.debugLog("dns_TIMEOUT: txn 0x\(String(txnID, radix: 16)), remaining=\(self.pendingQueries.count)")
                        self.sendServfail(for: pending, txnID: txnID)
                    }
                    self.checkForStall()
                }
                self.queue.asyncAfter(deadline: .now() + Self.queryTimeoutSeconds, execute: timeoutWork)
                if self.pendingQueries[txnID] != nil {
                    self.pendingQueries[txnID]?.deadline = timeoutWork
                }

                self.queriesSent += 1
                target.writeDatagram(payload) { [weak self] error in
                    guard let self = self, let error = error else { return }
                    os_log("DNS send error for txn 0x%04x: %{public}@", log: self.log, type: .error, txnID, error.localizedDescription)
                    self.queue.async {
                        if let pending = self.pendingQueries.removeValue(forKey: txnID) {
                            pending.deadline.cancel()
                        }
                    }
                }
                self.lastSendTime = CFAbsoluteTimeGetCurrent()
            }
        }
    }

    /// Called from wake() — ensure sessions are still alive after device sleep.
    /// Network path may have changed during sleep, silently killing sessions.
    func checkSessionsAfterWake() {
        queue.async { [weak self] in
            guard let self = self, !self.isShutdown else { return }
            // If we have pending queries but no recent responses, the sessions
            // may have died during sleep. Trigger stall check.
            if self.pendingQueries.count > 0, self.lastResponseTime > 0 {
                self.checkForStall()
            }
            // Ensure sessions exist (they may have been cancelled during sleep)
            self.ensureSession()
        }
    }

    private func failAllPendingQueries() {
        let count = pendingQueries.count
        for (_, pending) in pendingQueries {
            pending.deadline.cancel()
        }
        pendingQueries.removeAll()
        if count > 0 {
            debugLog("dns_drained: \(count) pending queries dropped")
        }
    }

    // MARK: - Query Lifecycle

    private func sendQuery(
        packet: Data,
        ipHeaderLen: Int,
        srcPort: UInt16,
        dnsPayload: Data,
        txnID: UInt16,
        protocolFamily: NSNumber,
        processResponse: @escaping (Data) -> Data
    ) {
        guard !isShutdown else { return }

        guard pendingQueries.count < Self.maxPendingQueries else {
            os_log("DNS query limit reached (%d), dropping", log: log, type: .error, Self.maxPendingQueries)
            queriesDropped += 1
            debugLog("dns_DROP: query limit \(Self.maxPendingQueries) reached, dropping txn 0x\(String(txnID, radix: 16))")
            return
        }

        // Transaction ID collision vs. retry:
        // - Same srcPort, same txnID → iOS retry (didn't get a response): replace and re-send.
        // - Different srcPort, same txnID → true collision between two apps: SERVFAIL the
        //   old query so it fails fast, then register the new one.
        var isRetry = false
        if let existing = pendingQueries.removeValue(forKey: txnID) {
            existing.deadline.cancel()
            if existing.srcPort == srcPort {
                // Genuine iOS retry — same app socket, same query
                isRetry = true
                debugLog("dns_RETRY: replacing stale txn 0x\(String(txnID, radix: 16)), pending=\(pendingQueries.count)")
            } else {
                // txnID collision from a different source port — SERVFAIL the evicted query
                debugLog("dns_COLLISION: txn 0x\(String(txnID, radix: 16)) srcPort \(existing.srcPort)→\(srcPort), SERVFAILing old, pending=\(pendingQueries.count)")
                sendServfail(for: existing, txnID: txnID)
            }
        }

        ensureSession()

        // Register the pending query WITHOUT starting the timeout yet.
        // The timeout starts when the query is actually sent (in doSend),
        // not when it's scheduled — prevents premature timeout for delayed queries.
        let timeoutHolder = PendingQueryTimeoutHolder()

        pendingQueries[txnID] = PendingQuery(
            originalPacket: packet,
            ipHeaderLen: ipHeaderLen,
            srcPort: srcPort,
            protocolFamily: protocolFamily,
            processResponse: processResponse,
            deadline: timeoutHolder.workItem // placeholder, replaced in doSend
        )

        // Primary-only sends by default; secondary used as failover on retry.
        let primaryReady = isSessionReady
        let secondaryReady = isSecondarySessionReady
        let primarySess = session
        let secondarySess = secondarySession

        let useSecondary = isRetry && secondaryReady
        let targetSession = useSecondary
            ? secondarySess
            : (primaryReady ? primarySess : secondarySess)

        if let targetSession = targetSession, (primaryReady || secondaryReady) {
            let now = CFAbsoluteTimeGetCurrent()
            let elapsed = (now - lastSendTime) * 1000
            let needsDelay = elapsed < Self.minSendIntervalMs

            let doSend = { [weak self] in
                guard let self = self, !self.isShutdown else { return }

                // Start the timeout NOW (when actually sending), not when scheduled
                let timeoutWork = DispatchWorkItem { [weak self] in
                    guard let self = self else { return }
                    if let pending = self.pendingQueries.removeValue(forKey: txnID) {
                        pending.deadline.cancel()
                        self.queriesTimedOut += 1
                        self.debugLog("dns_TIMEOUT: txn 0x\(String(txnID, radix: 16)), remaining=\(self.pendingQueries.count)")
                        self.sendServfail(for: pending, txnID: txnID)
                    }
                    self.checkForStall()
                }
                self.queue.asyncAfter(deadline: .now() + Self.queryTimeoutSeconds, execute: timeoutWork)

                // Update the pending entry's deadline to the real timeout
                if self.pendingQueries[txnID] != nil {
                    self.pendingQueries[txnID]?.deadline = timeoutWork
                }

                self.queriesSent += 1
                targetSession.writeDatagram(dnsPayload) { [weak self] error in
                    guard let self = self, let error = error else { return }
                    os_log("DNS send error txn 0x%04x: %{public}@", log: self.log, type: .error, txnID, error.localizedDescription)
                }

                self.lastSendTime = CFAbsoluteTimeGetCurrent()
            }

            if needsDelay {
                // No cap — each query gets its own delay slot at 50ms increments.
                // 62 queries = 3.1s spread. Each gets full 5s timeout after send.
                sendDelayCounter += 1
                let delay = Self.minSendIntervalMs / 1000.0 * Double(sendDelayCounter)
                queue.asyncAfter(deadline: .now() + delay, execute: doSend)
            } else {
                sendDelayCounter = 0
                doSend()
            }
        } else {
            // Cap queued sends to prevent unbounded memory growth before session ready
            if queuedSends.count >= Self.maxPendingQueries {
                debugLog("dns_QUEUE_FULL: dropping txn 0x\(String(txnID, radix: 16)), queue=\(queuedSends.count)")
                if let pending = pendingQueries.removeValue(forKey: txnID) {
                    pending.deadline.cancel()
                    sendServfail(for: pending, txnID: txnID)
                }
                return
            }
            queuedSends.append((dnsPayload, txnID))
            debugLog("dns_QUEUED: txn 0x\(String(txnID, radix: 16)) waiting for ready, queue=\(queuedSends.count)")
        }
    }

    private func handleResponse(data: Data, txnID: UInt16) {
        guard let pending = pendingQueries.removeValue(forKey: txnID) else {
            // Second response from dual-DNS (other server already answered) — harmless
            return
        }
        pending.deadline.cancel()
        responsesReceived += 1
        lastResponseTime = CFAbsoluteTimeGetCurrent()

        var responsePacket = buildIPv4UDPResponse(
            origPacket: pending.originalPacket,
            ipHeaderLen: pending.ipHeaderLen,
            dnsResponse: data,
            srcPort: pending.srcPort
        )

        responsePacket = pending.processResponse(responsePacket)
        packetFlow.writePackets([responsePacket], withProtocols: [pending.protocolFamily])
    }

    /// Synthesize a DNS SERVFAIL response so the app fails fast instead of hanging.
    private func sendServfail(for pending: PendingQuery, txnID: UInt16) {
        // Minimal DNS SERVFAIL: copy txnID from query, set QR=1, RCODE=2 (SERVFAIL)
        let origDNSOffset = pending.ipHeaderLen + 8  // IP header + UDP header
        guard pending.originalPacket.count > origDNSOffset + 12 else { return }

        // Extract the original DNS header (12 bytes) to preserve txnID and question
        let origDNS = pending.originalPacket.subdata(in: origDNSOffset..<pending.originalPacket.count)
        guard origDNS.count >= 12 else { return }

        // Build SERVFAIL response: copy header, set QR=1 + RCODE=2, zero answer/auth/additional
        var servfail = Data(count: 12)
        servfail[0] = origDNS[0]  // txnID high
        servfail[1] = origDNS[1]  // txnID low
        servfail[2] = 0x81        // QR=1, RD=1
        servfail[3] = 0x02        // RCODE=2 (SERVFAIL)
        servfail[4] = origDNS[4]  // QDCOUNT high
        servfail[5] = origDNS[5]  // QDCOUNT low
        servfail[6] = 0; servfail[7] = 0   // ANCOUNT = 0
        servfail[8] = 0; servfail[9] = 0   // NSCOUNT = 0
        servfail[10] = 0; servfail[11] = 0 // ARCOUNT = 0

        // Append the original question section
        if origDNS.count > 12 {
            servfail.append(origDNS.subdata(in: 12..<origDNS.count))
        }

        let responsePacket = buildIPv4UDPResponse(
            origPacket: pending.originalPacket,
            ipHeaderLen: pending.ipHeaderLen,
            dnsResponse: servfail,
            srcPort: pending.srcPort
        )
        packetFlow.writePackets([responsePacket], withProtocols: [pending.protocolFamily])
    }

    // MARK: - Stall Detection

    /// Detects when NWUDPSession read handlers have silently died.
    /// If no response has been received for `stallDetectionSeconds` while
    /// queries are pending, tear down both sessions and create new ones.
    private func checkForStall() {
        guard !isShutdown, pendingQueries.count >= 3 else { return }
        guard lastResponseTime > 0 else { return } // No responses yet — still starting up

        let elapsed = CFAbsoluteTimeGetCurrent() - lastResponseTime
        guard elapsed >= Self.stallDetectionSeconds else { return }

        sessionsRecreated += 1
        os_log("DNS stall detected (%.0fs no response, %d pending) — recreating sessions (#%d)",
               log: log, type: .error, elapsed, pendingQueries.count, sessionsRecreated)
        debugLog("dns_STALL: no response for \(Int(elapsed))s, pending=\(pendingQueries.count), recreating sessions (#\(sessionsRecreated))")

        // Tear down existing sessions
        if let sess = session {
            if !primaryObserverRemoved {
                sess.removeObserver(self, forKeyPath: "state")
                primaryObserverRemoved = true
            }
            sess.cancel()
        }
        session = nil
        isSessionReady = false

        if let sess = secondarySession {
            if !secondaryObserverRemoved {
                sess.removeObserver(self, forKeyPath: "state")
                secondaryObserverRemoved = true
            }
            sess.cancel()
        }
        secondarySession = nil
        isSecondarySessionReady = false

        // Reset response timer so we don't immediately re-trigger
        lastResponseTime = CFAbsoluteTimeGetCurrent()

        // Reset the rate-limit counter so re-queued sends on the new sessions
        // are not delayed by a counter that accumulated during the stalled session.
        sendDelayCounter = 0

        // Move all pending queries to the send queue so they'll be re-sent
        // on the new sessions instead of waiting for responses from dead ones.
        for (_, pending) in pendingQueries {
            pending.deadline.cancel()
        }
        let resendCount = pendingQueries.count
        pendingQueries.removeAll()
        debugLog("dns_STALL: cleared \(resendCount) pending queries (will be re-sent by iOS retries)")

        // Create fresh sessions — read handlers will be re-established
        ensureSession()
    }

    // MARK: - Packet Construction

    private func buildIPv4UDPResponse(origPacket: Data, ipHeaderLen: Int, dnsResponse: Data, srcPort: UInt16) -> Data {
        let udpLen = UInt16(8 + dnsResponse.count)
        let totalLen = UInt16(ipHeaderLen) + udpLen
        var pkt = Data(count: Int(totalLen))

        pkt[0] = origPacket[0]
        pkt[1] = 0
        pkt[2] = UInt8(totalLen >> 8)
        pkt[3] = UInt8(totalLen & 0xFF)
        pkt[4...5] = origPacket[4...5]
        pkt[6] = 0; pkt[7] = 0
        pkt[8] = 64
        pkt[9] = 17
        pkt[10] = 0; pkt[11] = 0
        pkt[12..<16] = origPacket[16..<20]
        pkt[16..<20] = origPacket[12..<16]

        var sum: UInt32 = 0
        for i in stride(from: 0, to: ipHeaderLen, by: 2) {
            sum += UInt32(pkt[i]) << 8 | UInt32(pkt[i + 1])
        }
        while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        let cksum = ~UInt16(sum & 0xFFFF)
        pkt[10] = UInt8(cksum >> 8)
        pkt[11] = UInt8(cksum & 0xFF)

        let uo = ipHeaderLen
        pkt[uo] = 0; pkt[uo + 1] = 53
        pkt[uo + 2] = UInt8(srcPort >> 8); pkt[uo + 3] = UInt8(srcPort & 0xFF)
        pkt[uo + 4] = UInt8(udpLen >> 8); pkt[uo + 5] = UInt8(udpLen & 0xFF)
        pkt[uo + 6] = 0; pkt[uo + 7] = 0

        pkt[(uo + 8)...] = dnsResponse[...]

        return pkt
    }

    // MARK: - DNS Parsing Helpers

    private static func extractDomainFromDNS(_ payload: Data) -> String? {
        guard payload.count > 12 else { return nil }
        var parts: [String] = []
        var offset = payload.startIndex + 12

        while offset < payload.endIndex {
            let labelLen = Int(payload[offset])
            if labelLen == 0 { break }
            offset += 1
            let labelEnd = offset + labelLen
            guard labelEnd <= payload.endIndex else { return nil }
            if let label = String(bytes: payload[offset..<labelEnd], encoding: .utf8) {
                parts.append(label)
            }
            offset = labelEnd
        }
        return parts.isEmpty ? nil : parts.joined(separator: ".")
    }
}
