import SwiftUI
import Combine
import NetworkExtension

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

    private let backendURL = "https://ring-backend-gccf.onrender.com"
    private let refreshTimer = Timer.publish(every: 5, on: .main, in: .common).autoconnect()

    // MARK: - Body

    var body: some View {
        List {
            systemSection
            collectionStatusSection
            sendSection
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

    // MARK: - Send Section

    private var sendSection: some View {
        Section {
            sendButton
        }
    }

    @ViewBuilder
    private var sendButton: some View {
        Button {
            guard sendState != .sending else { return }
            Task { await sendDiagnostics() }
        } label: {
            HStack {
                Spacer()
                sendButtonContent
                Spacer()
            }
            .padding(.vertical, 4)
        }
        .disabled(sendState == .sending)
        .listRowBackground(buttonBackground)
    }

    @ViewBuilder
    private var sendButtonContent: some View {
        switch sendState {
        case .idle:
            Label("Send Diagnostics", systemImage: "paperplane.fill")
                .font(.subheadline.weight(.semibold))
                .foregroundColor(.white)

        case .sending:
            HStack(spacing: 8) {
                ProgressView()
                    .tint(.white)
                Text("Sending...")
                    .font(.subheadline.weight(.semibold))
                    .foregroundColor(.white)
            }

        case .success:
            Label("Sent!", systemImage: "checkmark.circle.fill")
                .font(.subheadline.weight(.semibold))
                .foregroundColor(.white)

        case .failure(let message):
            VStack(spacing: 2) {
                Label("Failed to send", systemImage: "exclamationmark.circle.fill")
                    .font(.subheadline.weight(.semibold))
                    .foregroundColor(.white)
                Text(message)
                    .font(.caption)
                    .foregroundColor(.white.opacity(0.85))
                    .multilineTextAlignment(.center)
            }
        }
    }

    private var buttonBackground: Color {
        switch sendState {
        case .idle, .sending: return Theme.accent
        case .success:        return Theme.connected
        case .failure:        return Color(.systemRed)
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

    // MARK: - Send Diagnostics

    private func sendDiagnostics() async {
        sendState = .sending

        let payload = buildPayload()

        guard let url = URL(string: "\(backendURL)/api/diagnostics"),
              let jsonData = try? JSONSerialization.data(withJSONObject: payload) else {
            sendState = .failure("Invalid request")
            return
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = jsonData
        request.timeoutInterval = 15

        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            let statusCode = (response as? HTTPURLResponse)?.statusCode ?? -1
            if (200...299).contains(statusCode) {
                sendState = .success
                // Reset back to idle after showing success briefly
                try? await Task.sleep(nanoseconds: 2_000_000_000)
                sendState = .idle
            } else {
                sendState = .failure("Server returned \(statusCode)")
            }
        } catch {
            sendState = .failure(error.localizedDescription)
        }
    }

    // MARK: - Helpers

    private func buildPayload() -> [String: Any] {
        var payload: [String: Any] = [
            "device_id": ConsentService.shared.getOrCreateDeviceId(),
            "app_version": appVersion,
            "os_version": ProcessInfo.processInfo.operatingSystemVersionString,
            "vpn_status": vpnStatus,
            "db_size": dbFileSize,
            "tunnel_logs": tunnelStatus,
            "app_logs": logText
        ]
        if let stats = dbStats {
            payload["total_domains"] = stats.totalDomains
            payload["total_visits"] = stats.totalVisits
            payload["domains_today"] = stats.domainsToday
        }
        // Parse DNS stats from tunnel logs if available
        if let dnsLine = tunnelStatus.components(separatedBy: "\n")
            .last(where: { $0.contains("sent=") }) {
            let extract = { (key: String) -> Int? in
                guard let range = dnsLine.range(of: "\(key)=") else { return nil }
                let after = dnsLine[range.upperBound...]
                let numStr = after.prefix(while: { $0.isNumber })
                return Int(numStr)
            }
            if let v = extract("sent")    { payload["dns_sent"] = v }
            if let v = extract("ok")      { payload["dns_ok"] = v }
            if let v = extract("timeout") { payload["dns_timeout"] = v }
            if let v = extract("drop")    { payload["dns_dropped"] = v }
        }
        return payload
    }

    private func buildCombinedLog() -> String {
        var log = "=== Ring Diagnostics ===\n"
        log += "Date: \(Date())\n"
        log += "App: \(appVersion)\n"
        log += "iOS: \(ProcessInfo.processInfo.operatingSystemVersionString)\n"
        log += "VPN: \(vpnStatus)\n"
        log += "DB: \(dbFileSize)\n"
        if let s = dbStats {
            log += "Domains: \(s.totalDomains) | Visits: \(s.totalVisits) | Today: \(s.domainsToday)\n"
        }
        log += "\n=== TUNNEL LOGS ===\n"
        log += tunnelStatus.isEmpty ? "(empty)\n" : tunnelStatus
        log += "\n=== APP LOGS ===\n"
        log += logText.isEmpty ? "(empty)\n" : logText
        return log
    }

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
