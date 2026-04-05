import SwiftUI

/// Main security dashboard — combines VPN control + threat intelligence.
struct ThreatDashboardView: View {
    @EnvironmentObject var vpnManager: VPNManager
    @StateObject private var viewModel = ThreatDashboardViewModel()
    @StateObject private var connectionVM = ConnectionViewModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    // VPN control — shield button + status
                    vpnSection

                    // Live metrics (only when connected)
                    if connectionVM.status == .connected {
                        liveMetrics
                            .transition(.move(edge: .bottom).combined(with: .opacity))
                    }

                    // Threat stats row
                    HStack(spacing: 12) {
                        statCard(title: "Blocked", value: "\(viewModel.totalBlocked)", icon: "shield.checkered", color: Theme.threatRed)
                        statCard(title: "Today", value: "\(viewModel.blockedToday)", icon: "exclamationmark.triangle", color: Theme.threatOrange)
                        statCard(
                            title: "Protected",
                            value: viewModel.isLoadingFeeds ? "..." : viewModel.feedDomainCount,
                            icon: "lock.shield",
                            color: Theme.connected,
                            isLoading: viewModel.isLoadingFeeds
                        )
                    }
                    .redacted(reason: viewModel.isInitialLoad ? .placeholder : [])

                    // Threat type breakdown
                    if !viewModel.threatsByType.isEmpty {
                        threatBreakdownCard
                    }

                    // Recent threats
                    SectionHeader(title: "Recent Threats", count: viewModel.recentThreats.count)

                    if viewModel.recentThreats.isEmpty {
                        emptyState
                    } else {
                        LazyVStack(spacing: 0) {
                            ForEach(Array(viewModel.recentThreats.enumerated()), id: \.element.id) { index, threat in
                                if index > 0 {
                                    Divider().padding(.leading, 62)
                                }
                                NavigationLink(destination: ThreatDetailView(threat: threat)) {
                                    ThreatRowView(threat: threat)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                        .cardStyle()
                    }
                }
                .padding(16)
            }
            .background(Theme.pageBackground)
            .animation(.easeInOut(duration: 0.4), value: connectionVM.status)
            .navigationTitle("Sentinel")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink(destination: AllowlistView()) {
                        Image(systemName: "checklist")
                            .accessibilityLabel("Manage Allowlist")
                    }
                }
            }
            .refreshable {
                viewModel.refresh()
            }
            .onChange(of: scenePhase) { _, newPhase in
                if newPhase == .active {
                    viewModel.refresh()
                }
            }
            .alert("Connection Error", isPresented: Binding(
                get: { connectionVM.connectionError != nil },
                set: { if !$0 { connectionVM.connectionError = nil } }
            )) {
                Button("OK", role: .cancel) { connectionVM.connectionError = nil }
            } message: {
                Text(connectionVM.connectionError ?? "")
            }
        }
    }

    // MARK: - VPN Control Section

    private var vpnSection: some View {
        VStack(spacing: 12) {
            // Status label
            Text(statusText)
                .font(.system(size: 13, weight: .semibold))
                .foregroundColor(statusColor)
                .textCase(.uppercase)
                .tracking(1.5)

            // Shield button
            ConnectButton(status: connectionVM.status) {
                connectionVM.toggleConnection()
            }

            // Duration or hint
            if connectionVM.status == .connected {
                Text(connectionVM.formattedDuration)
                    .font(.system(size: 28, weight: .light, design: .monospaced))
                    .foregroundColor(.primary.opacity(0.6))
                    .transition(.opacity)
            } else {
                Text("Tap to enable protection")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
    }

    // MARK: - Live Metrics

    private var liveMetrics: some View {
        HStack(spacing: 10) {
            metricChip(value: connectionVM.formattedDomainsToday, label: "domains", color: Theme.accent)
            metricChip(value: connectionVM.formattedPacketsScanned, label: "packets", color: Theme.green)
            metricChip(value: connectionVM.formattedDNSQueries, label: "queries", color: Theme.yellow)
        }
    }

    private func metricChip(value: String, label: String, color: Color) -> some View {
        HStack(spacing: 5) {
            Text(value)
                .font(.system(size: 15, weight: .bold, design: .rounded))
            Text(label)
                .font(.system(size: 10))
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 10)
        .background(color.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(color.opacity(0.12), lineWidth: 1)
        )
    }

    // MARK: - Stat Card

    private func statCard(
        title: String,
        value: String,
        icon: String,
        color: Color,
        isLoading: Bool = false
    ) -> some View {
        VStack(spacing: 6) {
            Image(systemName: icon)
                .font(.caption)
                .foregroundColor(color)
                .accessibilityHidden(true)

            if isLoading {
                Text(value)
                    .font(.system(size: 13, weight: .medium, design: .rounded))
                    .foregroundStyle(.secondary)
            } else {
                Text(value)
                    .font(.system(size: 22, weight: .bold, design: .rounded))
            }

            Text(isLoading ? "Downloading..." : title)
                .font(.system(size: 10))
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 14)
        .background(color.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(color.opacity(0.15), lineWidth: 1)
        )
        .accessibilityElement(children: .combine)
    }

    // MARK: - Threat Breakdown

    private var threatBreakdownCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Threat Breakdown")
                .font(.caption.weight(.medium))
                .foregroundColor(.secondary)

            let maxCount = viewModel.threatsByType.map(\.count).max() ?? 1

            ForEach(viewModel.threatsByType, id: \.type) { entry in
                let record = ThreatRecord(
                    id: 0, domain: "", threatType: entry.type, feedName: "",
                    confidence: 0, timestampMs: 0, dismissed: false
                )
                let proportion = maxCount > 0 ? CGFloat(entry.count) / CGFloat(maxCount) : 0

                HStack(spacing: 10) {
                    Image(systemName: record.threatIcon)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(record.threatColor)
                        .frame(width: 24)
                        .accessibilityLabel("\(record.threatTypeDisplay) threat type")

                    Text(record.threatTypeDisplay)
                        .font(.system(size: 13, weight: .medium))
                        .frame(width: 80, alignment: .leading)

                    GeometryReader { geo in
                        ZStack(alignment: .leading) {
                            RoundedRectangle(cornerRadius: 3)
                                .fill(record.threatColor.opacity(0.12))
                                .frame(height: 6)
                            RoundedRectangle(cornerRadius: 3)
                                .fill(record.threatColor.gradient)
                                .frame(width: max(geo.size.width * proportion, 4), height: 6)
                        }
                    }
                    .frame(height: 6)

                    Text("\(entry.count)")
                        .font(.system(size: 13, weight: .bold, design: .rounded))
                        .foregroundStyle(.secondary)
                        .frame(width: 40, alignment: .trailing)
                }
            }
        }
        .padding(14)
        .cardStyle()
    }

    // MARK: - Empty State

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 48))
                .foregroundStyle(Theme.connected)

            Text("No threats detected")
                .font(.headline)

            Text("Sentinel is actively monitoring your connections")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 40)
    }

    // MARK: - Helpers

    private var statusText: String {
        switch connectionVM.status {
        case .connected: return "Protected"
        case .connecting: return "Connecting"
        case .disconnecting: return "Disconnecting"
        case .reasserting: return "Reconnecting"
        case .disconnected: return "Disconnected"
        case .invalid: return "Not Configured"
        @unknown default: return "Unknown"
        }
    }

    private var statusColor: Color {
        switch connectionVM.status {
        case .connected: return Theme.connected
        case .connecting, .disconnecting, .reasserting: return Theme.transitioning
        case .disconnected, .invalid: return Theme.accent.opacity(0.4)
        @unknown default: return Theme.accent.opacity(0.4)
        }
    }
}

#Preview {
    ThreatDashboardView()
        .environmentObject(VPNManager.shared)
}
