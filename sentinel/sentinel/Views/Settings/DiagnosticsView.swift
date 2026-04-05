import SwiftUI

struct DiagnosticsView: View {
    // MARK: - System section state

    @State private var logText = ""
    @State private var tunnelStatus = ""
    @State private var dbStats: DatabaseStats?
    @State private var vpnStatus: String = "Unknown"
    @State private var isVPNConnected = false
    @State private var dbFileSize: String = "—"

    // MARK: - Send state

    private enum SendState: Equatable {
        case idle
        case sending
        case success
        case failure(String)
    }

    @State private var sendState: SendState = .idle

    private let refreshTimer = Timer.publish(every: 5, on: .main, in: .common).autoconnect()

    // MARK: - Body

    var body: some View {
        List {
            systemSection
            collectionStatusSection
        }
        .navigationTitle("Diagnostics")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { loadAll() }
        .onReceive(refreshTimer) { _ in loadAll() }
    }

    // MARK: - System Section

    private var systemSection: some View {
        Section {
            infoRow("App Version", value: appVersion)
            infoRow("iOS", value: ProcessInfo.processInfo.operatingSystemVersionString)
            infoRow("VPN Status", value: vpnStatus)
            infoRow("DB Size", value: dbFileSize)
            if let stats = dbStats {
                infoRow("Domains", value: "\(stats.totalDomains)")
                infoRow("Visits", value: "\(stats.totalVisits)")
                infoRow("Today", value: "\(stats.domainsToday)")
            }
        } header: {
            Text("System")
                .font(.subheadline.weight(.semibold))
                .foregroundColor(.primary)
                .textCase(nil)
        }
    }

    // MARK: - Collection Status Section

    private var collectionStatusSection: some View {
        Section {
            HStack(spacing: 14) {
                Image(systemName: isVPNConnected ? "checkmark.circle.fill" : "circle.dashed")
                    .font(.title2)
                    .foregroundColor(isVPNConnected ? Theme.connected : .secondary)

                VStack(alignment: .leading, spacing: 3) {
                    Text(isVPNConnected ? "Collecting diagnostics" : "Connect VPN to start collecting diagnostics")
                        .font(.subheadline.weight(.medium))
                        .foregroundColor(isVPNConnected ? .primary : .secondary)

                    Text(logLineSummary)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .padding(.vertical, 4)
        }
    }

    // MARK: - Data Loading

    private func loadAll() {
        tunnelStatus = LogCollector.shared.readTunnelStatus()
        logText = LogCollector.shared.readAll()

        let status = VPNManager.shared.status
        switch status {
        case .connected:     vpnStatus = "Connected";     isVPNConnected = true
        case .connecting:    vpnStatus = "Connecting";    isVPNConnected = false
        case .disconnecting: vpnStatus = "Disconnecting"; isVPNConnected = false
        case .disconnected:  vpnStatus = "Disconnected";  isVPNConnected = false
        case .invalid:       vpnStatus = "Invalid";       isVPNConnected = false
        case .reasserting:   vpnStatus = "Reasserting";   isVPNConnected = true
        @unknown default:    vpnStatus = "Unknown";       isVPNConnected = false
        }

        dbStats = DatabaseReader.shared.stats()

        let path = AppGroupConfig.databasePath
        if let attrs = try? FileManager.default.attributesOfItem(atPath: path),
           let size = attrs[.size] as? Int64 {
            if size > 1_000_000 {
                dbFileSize = String(format: "%.1f MB", Double(size) / 1_000_000)
            } else {
                dbFileSize = String(format: "%.0f KB", Double(size) / 1_000)
            }
        } else {
            dbFileSize = "Not found"
        }
    }

    // MARK: - Helpers

    private func infoRow(_ label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(.subheadline)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .font(.subheadline.monospacedDigit())
        }
    }

    private var logLineSummary: String {
        let tunnelLines = lineCount(tunnelStatus)
        let appLines = lineCount(logText)
        return "Tunnel: \(tunnelLines) lines  ·  App: \(appLines) lines"
    }

    private func lineCount(_ text: String) -> Int {
        text.isEmpty ? 0 : text.components(separatedBy: "\n").filter { !$0.isEmpty }.count
    }

    private var appVersion: String {
        let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
        let b = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "?"
        return "\(v) (\(b))"
    }
}

#Preview {
    NavigationStack {
        DiagnosticsView()
    }
}
