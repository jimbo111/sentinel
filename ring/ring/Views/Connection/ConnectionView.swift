import SwiftUI
import NetworkExtension

struct ConnectionView: View {
    @EnvironmentObject var vpnManager: VPNManager
    @StateObject private var viewModel = ConnectionViewModel()
    @State private var recentSites: [SiteRecord] = []

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    // Hero: status + button + duration as one unit
                    heroSection

                    // Live session metrics (only when connected)
                    if viewModel.status == .connected {
                        liveMetrics
                            .transition(.move(edge: .bottom).combined(with: .opacity))
                    }

                    // Recent activity
                    if !recentSites.isEmpty {
                        recentSection
                    }
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 32)
            }
            .background(Theme.pageBackground)
            .animation(.easeInOut(duration: 0.4), value: viewModel.status)
            .navigationTitle("Ring")
            .navigationDestination(for: SiteRecord.self) { site in
                SiteDetailView(site: site)
            }
            .alert("Connection Error", isPresented: Binding(
                get: { viewModel.connectionError != nil },
                set: { if !$0 { viewModel.connectionError = nil } }
            )) {
                Button("OK", role: .cancel) { viewModel.connectionError = nil }
            } message: {
                Text(viewModel.connectionError ?? "")
            }
            .task { loadRecent() }
            .onReceive(NotificationCenter.default.publisher(for: .init(AppGroupConfig.newDomainsNotification))) { _ in
                loadRecent()
            }
        }
    }

    // MARK: - Hero Section

    private var heroSection: some View {
        VStack(spacing: 16) {
            Spacer().frame(height: 8)

            // Status text
            Text(statusText)
                .font(.system(size: 14, weight: .semibold))
                .foregroundColor(statusDotColor)
                .textCase(.uppercase)
                .tracking(1.5)

            // Connect button
            ConnectButton(status: viewModel.status) {
                viewModel.toggleConnection()
            }

            // Duration (below button, part of the hero)
            if viewModel.status == .connected {
                Text(viewModel.formattedDuration)
                    .font(.system(size: 32, weight: .light, design: .monospaced))
                    .foregroundColor(.primary.opacity(0.7))
                    .transition(.opacity)
            } else {
                Text("Tap to connect")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }

            Spacer().frame(height: 4)
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: - Live Metrics

    private var liveMetrics: some View {
        HStack(spacing: 10) {
            metricChip(value: viewModel.formattedDomainsToday, label: "domains", color: .blue)
            metricChip(value: viewModel.formattedPacketsScanned, label: "packets", color: .purple)
            metricChip(value: viewModel.formattedDNSQueries, label: "queries", color: .green)
        }
    }

    private func metricChip(value: String, label: String, color: Color) -> some View {
        HStack(spacing: 6) {
            Text(value)
                .font(.system(size: 16, weight: .bold, design: .rounded))

            Text(label)
                .font(.system(size: 11))
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12)
        .background(color.opacity(0.08))
        .cornerRadius(12)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(color.opacity(0.12), lineWidth: 1)
        )
    }

    // MARK: - Recent Activity

    private var recentSection: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Recent")
                    .font(.system(size: 18, weight: .semibold))

                Spacer()

                Text("\(recentSites.count) sites")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal, 4)
            .padding(.bottom, 12)

            VStack(spacing: 0) {
                ForEach(Array(recentSites.enumerated()), id: \.element.id) { index, site in
                    if index > 0 {
                        Divider().padding(.leading, 48)
                    }

                    let color = siteColor(site.siteDomain)

                    NavigationLink(value: site) {
                        HStack(spacing: 12) {
                            Circle()
                                .fill(color)
                                .frame(width: 10, height: 10)
                                .padding(.leading, 4)

                            VStack(alignment: .leading, spacing: 2) {
                                Text(site.siteDomain)
                                    .font(.system(size: 15, weight: .medium))
                                    .foregroundColor(.primary)
                                    .lineLimit(1)

                                Text(site.relativeTimeString)
                                    .font(.system(size: 12))
                                    .foregroundColor(.secondary)
                            }

                            Spacer()

                            Text("\(site.totalVisits)")
                                .font(.system(size: 14, weight: .semibold, design: .rounded))
                                .foregroundColor(color)
                        }
                        .padding(.vertical, 10)
                        .padding(.horizontal, 8)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.vertical, 4)
            .cardStyle()
        }
    }

    // MARK: - Helpers

    private func siteColor(_ domain: String) -> Color {
        Theme.colorForDomain(domain)
    }

    private func loadRecent() {
        recentSites = DatabaseReader.shared.recentSites(limit: 5)
    }

    private var statusText: String {
        switch viewModel.status {
        case .connected: return "Protected"
        case .connecting: return "Connecting"
        case .disconnecting: return "Disconnecting"
        case .reasserting: return "Reconnecting"
        case .disconnected: return "Disconnected"
        case .invalid: return "Not Configured"
        @unknown default: return "Unknown"
        }
    }

    private var statusDotColor: Color {
        switch viewModel.status {
        case .connected: return Theme.connected
        case .connecting, .disconnecting, .reasserting: return Theme.transitioning
        case .disconnected, .invalid: return Theme.accent.opacity(0.4)
        @unknown default: return Theme.accent.opacity(0.4)
        }
    }
}

struct StatCard: View {
    let title: String
    let value: String
    let icon: String

    var body: some View {
        VStack(spacing: 6) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundColor(Theme.accent)
                .frame(width: 40, height: 40)
                .background(Theme.accent.opacity(0.1))
                .cornerRadius(12)
            Text(value)
                .font(.system(.title3, design: .rounded).bold())
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 14)
        .background(Theme.pageBackground)
        .cornerRadius(Theme.cardRadius)
    }
}

#Preview {
    ConnectionView()
        .environmentObject(VPNManager.shared)
}
