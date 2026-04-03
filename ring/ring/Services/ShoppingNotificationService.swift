import Foundation
import UserNotifications

// MARK: - Notification Delegate

/// Shows notification banners even when the app is in the foreground.
final class NotificationDelegate: NSObject, UNUserNotificationCenterDelegate {
    static let shared = NotificationDelegate()

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }
}

// MARK: - Shopping Notification Service

@MainActor
final class ShoppingNotificationService {
    static let shared = ShoppingNotificationService()

    private let notificationListener = DarwinNotificationListener(
        name: AppGroupConfig.newDomainsNotification
    )

    private static let debounceSeconds: TimeInterval = 3600 // 1 hour
    private static let timestampsKey = "shopping_notification_timestamps"

    /// Throttle: don't query DB more than once per 3 seconds.
    private var lastCheckTime: CFAbsoluteTime = 0
    private static let checkThrottleSeconds: CFAbsoluteTime = 3.0

    private init() {}

    // MARK: - Public API

    func startListening() {
        // Set delegate so notifications display as banners even in foreground
        UNUserNotificationCenter.current().delegate = NotificationDelegate.shared

        notificationListener.startListening { [weak self] in
            Task { @MainActor [weak self] in
                self?.onNewDomains()
            }
        }
    }

    func stopListening() {
        notificationListener.stopListening()
    }

    // MARK: - Notification Logic

    private func onNewDomains() {
        let now = CFAbsoluteTimeGetCurrent()
        guard now - lastCheckTime >= Self.checkThrottleSeconds else { return }
        lastCheckTime = now

        guard UserSettings().showShoppingNotifications else { return }

        Task {
            await checkAndNotify()
        }
    }

    private func checkAndNotify() async {
        let sites = Task.detached(priority: .userInitiated) {
            DatabaseReader.shared.recentSites(limit: 10)
        }
        let recentSites = await sites.value

        for site in recentSites {
            guard let cat = CategoriesService.shared.categorize(site.siteDomain),
                  cat.key == "shopping" else { continue }

            let domain = site.siteDomain
            guard shouldNotify(domain: domain) else { continue }

            guard await ensurePermission() else { return }

            fireNotification(for: domain)
            recordNotification(domain: domain)
            // One notification per check cycle — don't spam
            return
        }
    }

    // MARK: - Debounce

    private func shouldNotify(domain: String) -> Bool {
        let timestamps = loadTimestamps()
        guard let lastFired = timestamps[domain] else { return true }
        return Date().timeIntervalSince1970 - lastFired >= Self.debounceSeconds
    }

    private func recordNotification(domain: String) {
        var timestamps = loadTimestamps()
        let now = Date().timeIntervalSince1970
        timestamps[domain] = now

        // Prune entries older than 48 hours to prevent unbounded growth
        let cutoff = now - 172800
        timestamps = timestamps.filter { $0.value > cutoff }

        AppGroupConfig.sharedDefaults.set(timestamps, forKey: Self.timestampsKey)
    }

    private func loadTimestamps() -> [String: TimeInterval] {
        AppGroupConfig.sharedDefaults.dictionary(forKey: Self.timestampsKey) as? [String: TimeInterval] ?? [:]
    }

    // MARK: - Permission

    private func ensurePermission() async -> Bool {
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()

        switch settings.authorizationStatus {
        case .authorized, .provisional:
            return true
        case .notDetermined:
            do {
                return try await center.requestAuthorization(options: [.alert, .sound])
            } catch {
                return false
            }
        default:
            return false
        }
    }

    // MARK: - Fire Notification

    private func fireNotification(for domain: String) {
        let (title, body) = dealMessage(for: domain)

        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        content.categoryIdentifier = "shopping_deal"
        content.interruptionLevel = .timeSensitive

        // Delay notification by 5 seconds so it doesn't fire the instant
        // the user lands on the site — feels more natural, like a timely tip.
        let trigger = UNTimeIntervalNotificationTrigger(timeInterval: 5, repeats: false)

        // Identifier includes domain — system deduplicates by ID
        let identifier = "ring-shopping-\(domain)"
        let request = UNNotificationRequest(identifier: identifier, content: content, trigger: trigger)

        UNUserNotificationCenter.current().add(request) { error in
            if let error {
                LogCollector.shared.log("shopping-notif: FAILED \(error.localizedDescription)", source: "notification")
            } else {
                LogCollector.shared.log("shopping-notif: fired for \(domain)", source: "notification")
            }
        }
    }

    // MARK: - Deal Messages

    private func dealMessage(for domain: String) -> (title: String, body: String) {
        if let custom = Self.dealMessages[domain] {
            return custom
        }
        // Fallback: derive store name from domain
        let storeName = domain.split(separator: ".").first.map(String.init)?.capitalized ?? domain
        return (storeName, "Deals may be available — check for savings!")
    }

    private static let dealMessages: [String: (title: String, body: String)] = [
        // Korean
        "coupang.com":        ("Coupang",        "Check today's Lightning Deals! ⚡"),
        "gmarket.co.kr":      ("Gmarket",        "New Super Deals just dropped!"),
        "11st.co.kr":         ("11st",           "Today's exclusive offers are live!"),
        "musinsa.com":        ("Musinsa",        "New arrivals and limited deals available!"),
        "kurly.com":          ("Market Kurly",   "Fresh daily deals on groceries!"),
        "ssg.com":            ("SSG",            "Check today's special prices!"),
        "lotteon.com":        ("Lotte ON",       "New deals and coupons available!"),
        "oliveyoung.co.kr":   ("Olive Young",    "Beauty deals waiting for you!"),
        "tmon.com":           ("TMON",           "Time-limited deals are live!"),
        "wemakeprice.com":    ("WeMakePrice",    "Today's best prices are here!"),
        "ohou.se":            ("Today's House",  "Home & living deals available!"),
        "zigzag.kr":          ("Zigzag",         "Fashion picks and deals for you!"),
        "29cm.co.kr":         ("29CM",           "Curated picks on sale today!"),
        "danawa.com":         ("Danawa",         "Compare prices and find the best deal!"),
        // Global
        "amazon.com":         ("Amazon",         "Today's deals are live!"),
        "walmart.com":        ("Walmart",        "Rollback deals available now!"),
        "target.com":         ("Target",         "Check today's Circle offers!"),
        "bestbuy.com":        ("Best Buy",       "Deal of the Day is live!"),
        "nike.com":           ("Nike",           "New drops and member exclusives!"),
        "costco.com":         ("Costco",         "Member-only deals available!"),
        "ebay.com":           ("eBay",           "Daily Deals just refreshed!"),
        "etsy.com":           ("Etsy",           "Handmade finds with special pricing!"),
        "shein.com":          ("SHEIN",          "Flash sale happening now!"),
        "temu.com":           ("Temu",           "Today's lowest prices are here!"),
        "ikea.com":           ("IKEA",           "Home furnishing deals available!"),
        "zara.com":           ("Zara",           "New collection and sale items!"),
        "adidas.com":         ("Adidas",         "Member deals and new drops!"),
        "uniqlo.com":         ("Uniqlo",         "Limited-time offers available!"),
    ]
}
