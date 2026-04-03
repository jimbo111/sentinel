import Foundation

final class ConsentService {
    static let shared = ConsentService()

    private let baseURL = "https://ring-backend-gccf.onrender.com"

    private init() {}

    /// Whether the backend has acknowledged our consent.
    var isConsentSynced: Bool {
        AppGroupConfig.sharedDefaults.bool(forKey: "consent_synced_to_backend")
    }

    func sendConsent(dnsTelemetry: Bool, usageAnalytics: Bool, crashReports: Bool) async {
        // Reset sync flag so a failed send doesn't leave stale "synced" state
        // from a previous successful send with different consent values.
        AppGroupConfig.sharedDefaults.set(false, forKey: "consent_synced_to_backend")

        let deviceId = getOrCreateDeviceId()

        let body: [String: Any] = [
            "device_id": deviceId,
            "consents": [
                "dns_telemetry": dnsTelemetry,
                "usage_analytics": usageAnalytics,
                "crash_reports": crashReports
            ],
            "app_version": Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown",
            "os_version": ProcessInfo.processInfo.operatingSystemVersionString
        ]

        guard let url = URL(string: "\(baseURL)/api/consent"),
              let jsonData = try? JSONSerialization.data(withJSONObject: body) else { return }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = jsonData
        request.timeoutInterval = 10

        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            if let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 201 || httpResponse.statusCode == 200 {
                AppGroupConfig.sharedDefaults.set(true, forKey: "consent_synced_to_backend")
                LogCollector.shared.log("consent: synced, status=\(httpResponse.statusCode)", source: "consent")
            } else {
                LogCollector.shared.log("consent: unexpected status \((response as? HTTPURLResponse)?.statusCode ?? -1)", source: "consent")
            }
        } catch {
            LogCollector.shared.log("consent: FAILED \(error.localizedDescription)", source: "consent")
        }
    }

    /// Re-send consent from local storage if the backend hasn't acknowledged it yet.
    func retrySyncIfNeeded() async {
        guard !isConsentSynced else { return }

        let defaults = AppGroupConfig.sharedDefaults
        let dns = defaults.bool(forKey: "consent_dns_telemetry")
        let analytics = defaults.bool(forKey: "consent_usage_analytics")
        let crashes = defaults.bool(forKey: "consent_crash_reports")

        // Only retry if the user has completed the consent screen.
        // hasCompletedConsent is stored via @AppStorage in UserDefaults.standard.
        guard UserDefaults.standard.bool(forKey: "hasCompletedConsent") else { return }

        LogCollector.shared.log("consent: retrying sync", source: "consent")
        await sendConsent(dnsTelemetry: dns, usageAnalytics: analytics, crashReports: crashes)
    }

    private static let keychainService = "com.jimmykim.sentinel"
    private static let keychainAccount = "device_id"

    func getOrCreateDeviceId() -> String {
        // Try Keychain first (persists across reinstalls)
        if let existing = readKeychainDeviceId() {
            return existing
        }

        // Migrate from UserDefaults if present (one-time migration)
        let defaults = AppGroupConfig.sharedDefaults
        if let legacyId = defaults.string(forKey: "ring_device_id") {
            saveKeychainDeviceId(legacyId)
            return legacyId
        }

        // Generate new ID and store in Keychain
        let newId = UUID().uuidString
        saveKeychainDeviceId(newId)
        defaults.set(newId, forKey: "ring_device_id") // Keep UserDefaults copy for tunnel extension
        return newId
    }

    private func readKeychainDeviceId() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: Self.keychainAccount,
            kSecReturnData as String: true,
            kSecAttrAccessGroup as String: "9JYD5XU49X.group.com.jimmykim.sentinel"
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func saveKeychainDeviceId(_ deviceId: String) {
        let data = Data(deviceId.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: Self.keychainAccount,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
            kSecAttrAccessGroup as String: "9JYD5XU49X.group.com.jimmykim.sentinel"
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        if status == errSecDuplicateItem {
            let update: [String: Any] = [kSecValueData as String: data]
            SecItemUpdate(query as CFDictionary, update as CFDictionary)
        }
    }
}
