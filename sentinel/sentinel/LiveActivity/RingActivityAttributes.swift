import ActivityKit
import Foundation

struct SentinelActivityAttributes: ActivityAttributes {
    /// Dynamic data that updates during the Live Activity lifecycle.
    struct ContentState: Codable, Hashable {
        var isConnected: Bool
        var domainsToday: Int
        var totalVisits: Int
        var lastDomain: String
        /// The date the VPN session started. Used with `Text(date, style: .timer)`
        /// so the system renders a live-updating elapsed timer without pushes.
        var sessionStartDate: Date
    }
}
