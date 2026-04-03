import Foundation

struct InsightsCategory: Identifiable, Hashable {
    let category: String
    let label: String
    let siteCount: Int
    let totalVisits: Int
    let totalDomains: Int
    let percentage: Int
    let sites: [InsightsSite]

    var id: String { category }
}

struct InsightsSite: Identifiable, Hashable {
    let domain: String
    let visits: Int
    let domains: Int

    var id: String { domain }
}

struct InsightsResponse {
    let totalVisits: Int
    let categoryCount: Int
    let insights: [InsightsCategory]
}

final class InsightsService {
    static let shared = InsightsService()

    private let baseURL = "https://ring-backend-gccf.onrender.com"
    private var cached: InsightsResponse?
    private var lastFetch: Date?

    private init() {}

    var cachedInsights: InsightsResponse? { cached }

    func fetchInsights(forceRefresh: Bool = false) async -> InsightsResponse? {
        // Return cache if fresh (< 60s) and not forced
        if !forceRefresh, let cached = cached, let lastFetch = lastFetch,
           Date().timeIntervalSince(lastFetch) < 60 {
            return cached
        }

        guard let deviceId = AppGroupConfig.sharedDefaults.string(forKey: "ring_device_id") else {
            LogCollector.shared.log("insights: no device_id", source: "insights")
            return cached
        }

        guard let url = URL(string: "\(baseURL)/api/config/insights?device_id=\(deviceId)") else {
            return cached
        }

        var request = URLRequest(url: url)
        request.timeoutInterval = 10

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
                LogCollector.shared.log("insights: status \((response as? HTTPURLResponse)?.statusCode ?? -1)", source: "insights")
                return cached
            }

            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                return cached
            }

            let totalVisits = json["totalVisits"] as? Int ?? 0
            let categoryCount = json["categoryCount"] as? Int ?? 0
            let rawInsights = json["insights"] as? [[String: Any]] ?? []

            let insights: [InsightsCategory] = rawInsights.compactMap { item in
                guard let category = item["category"] as? String,
                      let label = item["label"] as? String else { return nil }

                let rawSites = item["sites"] as? [[String: Any]] ?? []
                let sites: [InsightsSite] = rawSites.compactMap { s in
                    guard let domain = s["domain"] as? String else { return nil }
                    return InsightsSite(
                        domain: domain,
                        visits: s["visits"] as? Int ?? 0,
                        domains: s["domains"] as? Int ?? 0
                    )
                }

                return InsightsCategory(
                    category: category,
                    label: label,
                    siteCount: item["siteCount"] as? Int ?? 0,
                    totalVisits: item["totalVisits"] as? Int ?? 0,
                    totalDomains: item["totalDomains"] as? Int ?? 0,
                    percentage: item["percentage"] as? Int ?? 0,
                    sites: sites
                )
            }

            let result = InsightsResponse(
                totalVisits: totalVisits,
                categoryCount: categoryCount,
                insights: insights
            )
            cached = result
            lastFetch = Date()
            LogCollector.shared.log("insights: fetched \(insights.count) categories, \(totalVisits) visits", source: "insights")
            return result
        } catch {
            LogCollector.shared.log("insights: FAILED \(error.localizedDescription)", source: "insights")
            return cached
        }
    }
}
