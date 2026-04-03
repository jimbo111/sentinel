import Foundation

final class ConfigService {
    static let shared = ConfigService()

    private let baseURL = "https://ring-backend-gccf.onrender.com"
    private let cacheKey = "cached_resolved_associations"
    private let etagKey = "associations_etag"

    private init() {}

    /// Cached resolved associations: cdn_domain -> parent_site
    var resolvedAssociations: [String: String] {
        let defaults = AppGroupConfig.sharedDefaults
        return defaults.dictionary(forKey: cacheKey) as? [String: String] ?? [:]
    }

    /// Fetch updated associations from backend. Call on app launch.
    func fetchUpdatedMappings() async {
        await fetchResolvedAssociations()
        LogCollector.shared.log("config: fetch complete, \(resolvedAssociations.count) resolved associations cached", source: "config")
    }

    /// Remap a site_domain using backend-resolved associations.
    /// If the domain has a backend override, returns the override. Otherwise returns the original.
    func remapSiteDomain(_ siteDomain: String) -> String {
        return resolvedAssociations[siteDomain] ?? siteDomain
    }

    private func fetchResolvedAssociations() async {
        guard let url = URL(string: "\(baseURL)/api/config/resolved") else { return }

        var request = URLRequest(url: url)
        request.timeoutInterval = 10

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200 else { return }

            guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let resolved = json["resolved"] as? [[String: Any]] else { return }

            var mapping: [String: String] = [:]
            for entry in resolved {
                if let cdn = entry["cdn_domain"] as? String,
                   let parent = entry["parent_site"] as? String {
                    mapping[cdn] = parent
                }
            }

            AppGroupConfig.sharedDefaults.set(mapping, forKey: cacheKey)
            LogCollector.shared.log("config: cached \(mapping.count) resolved associations", source: "config")
        } catch {
            LogCollector.shared.log("config: fetch failed \(error.localizedDescription)", source: "config")
        }
    }
}
