import Foundation
import UserNotifications
import os.log

/// Manages local notifications for threat detections.
///
/// Rate-limited to at most one notification per 30 seconds to avoid
/// spamming the user during a burst of blocked queries. Supports
/// actionable notifications with "View Details" and "Allowlist" buttons.
final class ThreatAlertService: NSObject {
    static let shared = ThreatAlertService()

    private let log = OSLog(subsystem: "com.jimmykim.ring", category: "ThreatAlertService")

    /// Minimum interval between notifications (seconds).
    private let rateLimitInterval: TimeInterval = 30
    private var lastNotificationDate: Date?

    static let categoryIdentifier = "THREAT_BLOCKED"
    static let viewDetailsAction = "VIEW_DETAILS"
    static let allowlistAction = "ALLOWLIST"

    private override init() {
        super.init()
        registerCategories()
    }

    // MARK: - Public API

    /// Request notification permission. Returns true if granted.
    @discardableResult
    func requestPermission() async -> Bool {
        do {
            let granted = try await UNUserNotificationCenter.current()
                .requestAuthorization(options: [.alert, .sound, .badge])
            if granted {
                os_log(.info, log: log, "Notification permission granted")
            } else {
                os_log(.info, log: log, "Notification permission denied")
            }
            return granted
        } catch {
            os_log(.error, log: log, "Notification permission request failed: %{public}@", error.localizedDescription)
            return false
        }
    }

    /// Send a local notification for a blocked threat.
    /// Rate-limited: silently drops if called within 30s of the last notification.
    func notifyThreatBlocked(domain: String, threatType: String, feedName: String) {
        let now = Date()
        if let last = lastNotificationDate, now.timeIntervalSince(last) < rateLimitInterval {
            os_log(.debug, log: log, "Notification rate-limited for %{public}@", domain)
            return
        }
        lastNotificationDate = now

        let content = UNMutableNotificationContent()
        content.title = "Threat Blocked"
        content.body = "Sentinel blocked \(domain) (\(displayName(for: threatType)))"
        content.sound = .default
        content.categoryIdentifier = Self.categoryIdentifier
        content.userInfo = [
            "domain": domain,
            "threatType": threatType,
            "feedName": feedName,
        ]

        let request = UNNotificationRequest(
            identifier: "threat-\(domain)-\(Int(now.timeIntervalSince1970))",
            content: content,
            trigger: nil // deliver immediately
        )

        UNUserNotificationCenter.current().add(request) { [weak self] error in
            if let error {
                os_log(.error, log: self?.log ?? .default,
                       "Failed to schedule threat notification: %{public}@",
                       error.localizedDescription)
            }
        }
    }

    /// Schedule a daily summary notification at 9:00 AM.
    func scheduleDailySummary(blockedCount: Int) {
        guard blockedCount > 0 else { return }

        let content = UNMutableNotificationContent()
        content.title = "Daily Security Summary"
        content.body = "Sentinel blocked \(blockedCount) threat\(blockedCount == 1 ? "" : "s") today."
        content.sound = .default

        var dateComponents = DateComponents()
        dateComponents.hour = 9
        dateComponents.minute = 0

        let trigger = UNCalendarNotificationTrigger(dateMatching: dateComponents, repeats: false)

        let request = UNNotificationRequest(
            identifier: "daily-summary",
            content: content,
            trigger: trigger
        )

        UNUserNotificationCenter.current().add(request) { [weak self] error in
            if let error {
                os_log(.error, log: self?.log ?? .default,
                       "Failed to schedule daily summary: %{public}@",
                       error.localizedDescription)
            }
        }
    }

    // MARK: - Private

    private func registerCategories() {
        let viewAction = UNNotificationAction(
            identifier: Self.viewDetailsAction,
            title: "View Details",
            options: [.foreground]
        )
        let allowlistAction = UNNotificationAction(
            identifier: Self.allowlistAction,
            title: "Allowlist",
            options: [.destructive]
        )

        let category = UNNotificationCategory(
            identifier: Self.categoryIdentifier,
            actions: [viewAction, allowlistAction],
            intentIdentifiers: [],
            hiddenPreviewsBodyPlaceholder: "Threat blocked",
            options: []
        )

        UNUserNotificationCenter.current().setNotificationCategories([category])
    }

    private func displayName(for threatType: String) -> String {
        switch threatType {
        case "phishing": return "Phishing"
        case "malware": return "Malware"
        case "command": return "C2 Server"
        case "tracking": return "Tracker"
        default: return "Threat"
        }
    }
}
