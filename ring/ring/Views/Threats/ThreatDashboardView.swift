import SwiftUI

/// Main security dashboard showing threat statistics and recent blocked threats.
struct ThreatDashboardView: View {
    @StateObject private var viewModel = ThreatDashboardViewModel()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    // Hero card: total threats blocked
                    ThreatCountCard(count: viewModel.totalBlocked, period: "All Time")

                    // Today's stats row
                    HStack(spacing: 12) {
                        statCard(title: "Today", value: "\(viewModel.blockedToday)", icon: "shield.checkered", color: Theme.threatRed)
                        statCard(title: "Feeds", value: "\(viewModel.feedsLoaded)", icon: "antenna.radiowaves.left.and.right", color: Theme.accent)
                        statCard(title: "Protected", value: viewModel.feedDomainCount, icon: "lock.shield", color: Theme.connected)
                    }

                    // Threat type breakdown (if data exists)
                    if !viewModel.threatsByType.isEmpty {
                        threatBreakdownCard
                    }

                    // Recent threats list
                    SectionHeader(title: "Recent Threats", count: viewModel.recentThreats.count)

                    if viewModel.recentThreats.isEmpty {
                        emptyState
                    } else {
                        VStack(spacing: 0) {
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
            .navigationTitle("Security")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink(destination: AllowlistView()) {
                        Image(systemName: "checklist")
                    }
                }
            }
            .refreshable {
                viewModel.refresh()
            }
        }
    }

    // MARK: - Stat Card

    private func statCard(title: String, value: String, icon: String, color: Color) -> some View {
        VStack(spacing: 6) {
            Image(systemName: icon)
                .font(.caption)
                .foregroundColor(color)

            Text(value)
                .font(.system(size: 22, weight: .bold, design: .rounded))

            Text(title)
                .font(.system(size: 11))
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 14)
        .background(color.opacity(0.08))
        .cornerRadius(12)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(color.opacity(0.15), lineWidth: 1)
        )
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
}

#Preview {
    ThreatDashboardView()
}
