import Foundation

final class TelemetryService {
    static let shared = TelemetryService()

    private let baseURL = "https://ring-backend-gccf.onrender.com"
    private static let lastSyncKey = "telemetry_last_sync_ms"

    private init() {}

    /// Timestamp (ms since epoch) of the last successful telemetry sync.
    private var lastSyncMs: Int64 {
        get { Int64(AppGroupConfig.sharedDefaults.double(forKey: Self.lastSyncKey)) }
        set { AppGroupConfig.sharedDefaults.set(Double(newValue), forKey: Self.lastSyncKey) }
    }

    var hasDnsTelemetryConsent: Bool {
        AppGroupConfig.sharedDefaults.bool(forKey: "consent_dns_telemetry")
    }

    func syncTelemetry() async {
        guard hasDnsTelemetryConsent else {
            LogCollector.shared.log("telemetry: skipped, no consent", source: "telemetry")
            return
        }

        // Ensure consent is synced to backend before sending telemetry
        if !ConsentService.shared.isConsentSynced {
            await ConsentService.shared.retrySyncIfNeeded()
            // If still not synced, skip telemetry (backend will 403)
            guard ConsentService.shared.isConsentSynced else {
                LogCollector.shared.log("telemetry: skipped, consent not synced to backend", source: "telemetry")
                return
            }
        }

        let deviceId = AppGroupConfig.sharedDefaults.string(forKey: "ring_device_id")
        guard let deviceId = deviceId else {
            LogCollector.shared.log("telemetry: skipped, no device_id", source: "telemetry")
            return
        }

        let allSites = DatabaseReader.shared.recentSites(limit: 500)
        // Only include sites that have been updated since last sync
        let sinceMs = lastSyncMs
        let sites = sinceMs > 0
            ? allSites.filter { $0.lastSeenMs > sinceMs }
            : allSites
        guard !sites.isEmpty else {
            LogCollector.shared.log("telemetry: skipped, no new sites since last sync", source: "telemetry")
            return
        }
        LogCollector.shared.log("telemetry: syncing \(sites.count) sites (filtered from \(allSites.count))", source: "telemetry")

        let domainEvents = sites.map { site -> [String: Any] in
            [
                "site_domain": site.siteDomain,
                "layer": 0,
                "visit_count": site.totalVisits,
                "domain_count": site.domainCount
            ]
        }

        let stats = DatabaseReader.shared.stats()

        let body: [String: Any] = [
            "device_id": deviceId,
            "session_id": UUID().uuidString,
            "mapping_version": 1,
            "duration_sec": 0,
            "domain_events": domainEvents,
            "unmapped_domains": [] as [[String: Any]],
            "query_volume": [
                "total": stats.totalVisits,
                "noise_filtered": 0,
                "unique_sites": sites.count,
                "unique_domains": stats.totalDomains
            ]
        ]

        let syncTimestamp = Int64(Date().timeIntervalSince1970 * 1000)
        if await send(endpoint: "/api/telemetry", body: body) {
            lastSyncMs = syncTimestamp
        }
    }

    @discardableResult
    private func send(endpoint: String, body: [String: Any]) async -> Bool {
        guard let url = URL(string: "\(baseURL)\(endpoint)"),
              let jsonData = try? JSONSerialization.data(withJSONObject: body) else { return false }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = jsonData
        request.timeoutInterval = 15

        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            if let httpResponse = response as? HTTPURLResponse {
                LogCollector.shared.log("telemetry: sent, status=\(httpResponse.statusCode)", source: "telemetry")
                return (200...299).contains(httpResponse.statusCode)
            }
            return false
        } catch {
            LogCollector.shared.log("telemetry: FAILED \(error.localizedDescription)", source: "telemetry")
            return false
        }
    }
}
