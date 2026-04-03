import Foundation
import Combine

/// ViewModel for the threat dashboard. Reads from the shared SQLite database
/// and listens for Darwin notifications from the Network Extension when new
/// threats are detected.
@MainActor
final class ThreatDashboardViewModel: ObservableObject {
    @Published var totalBlocked: Int = 0
    @Published var blockedToday: Int = 0
    @Published var feedsLoaded: Int = 0
    @Published var feedDomainCount: String = "0"
    @Published var recentThreats: [ThreatRecord] = []
    @Published var threatsByType: [(type: String, count: Int)] = []

    private var listener: DarwinNotificationListener?

    init() {
        refresh()

        // Listen for new threat alerts from the Network Extension
        listener = DarwinNotificationListener(name: AppGroupConfig.threatAlertNotification)
        listener?.startListening { [weak self] in
            self?.refresh()
        }
    }

    func refresh() {
        let db = DatabaseReader.shared
        totalBlocked = db.fetchAlertCount()

        let todayStart = Calendar.current.startOfDay(for: Date())
        blockedToday = db.fetchAlertCountSince(todayStart)

        recentThreats = db.fetchRecentAlerts(limit: 50)
        threatsByType = db.fetchThreatsByType()

        // Read feed stats from shared UserDefaults written by the extension
        let defaults = UserDefaults(suiteName: AppGroupConfig.groupIdentifier)
        let storedFeedsLoaded = defaults?.integer(forKey: "sentinel_feeds_loaded") ?? 0
        let storedFeedDomainCount = defaults?.integer(forKey: "sentinel_feed_domain_count") ?? 0

        feedsLoaded = storedFeedsLoaded > 0 ? storedFeedsLoaded : ThreatFeedService.feeds.count
        feedDomainCount = Self.formatCompact(storedFeedDomainCount)
    }

    /// Formats a number compactly: 1234 -> "1.2K", 1234567 -> "1.2M"
    private static func formatCompact(_ value: Int) -> String {
        if value >= 1_000_000 {
            return String(format: "%.1fM", Double(value) / 1_000_000)
        } else if value >= 1_000 {
            return String(format: "%.0fK", Double(value) / 1_000)
        } else {
            return "\(value)"
        }
    }
}
