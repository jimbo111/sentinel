import Foundation
import os.log

/// Downloads and caches threat intelligence feeds for the Sentinel engine.
/// Feeds are stored as plain text files in the App Group container so both
/// the main app and the Network Extension can read them.
actor ThreatFeedService {
    static let shared = ThreatFeedService()

    private let log = OSLog(subsystem: "com.jimmykim.sentinel", category: "ThreatFeedService")

    struct FeedConfig {
        let name: String
        let url: URL
        let filename: String
    }

    static let feeds: [FeedConfig] = [
        FeedConfig(
            name: "hagezi-pro",
            url: URL(string: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/hosts/pro.txt")!,
            filename: "hagezi-pro.txt"
        ),
        FeedConfig(
            name: "urlhaus-malware",
            url: URL(string: "https://urlhaus.abuse.ch/downloads/hostfile/")!,
            filename: "urlhaus-hosts.txt"
        ),
    ]

    private static let lastUpdatedKeyPrefix = "threatfeed_updated_"

    // MARK: - Public API

    /// Download all feeds from remote. Returns array of (feedName, data) for loading into the engine.
    /// Falls back to cached data per-feed when a download fails.
    func refreshFeeds() async -> [(name: String, data: String)] {
        var results: [(name: String, data: String)] = []

        for feed in Self.feeds {
            do {
                let (data, response) = try await URLSession.shared.data(from: feed.url)
                guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
                    os_log(.error, log: log, "Feed %{public}@ returned non-200 status", feed.name)
                    // Fall back to cache
                    if let cached = readCachedFeed(filename: feed.filename) {
                        results.append((name: feed.name, data: cached))
                    }
                    continue
                }

                guard let text = String(data: data, encoding: .utf8) else {
                    os_log(.error, log: log, "Feed %{public}@ data is not valid UTF-8", feed.name)
                    if let cached = readCachedFeed(filename: feed.filename) {
                        results.append((name: feed.name, data: cached))
                    }
                    continue
                }

                // Write to App Group container
                let path = feedPath(filename: feed.filename)
                try data.write(to: path, options: .atomic)

                // Store last-updated timestamp
                let defaults = UserDefaults(suiteName: AppGroupConfig.groupIdentifier)
                defaults?.set(Date().timeIntervalSince1970, forKey: Self.lastUpdatedKeyPrefix + feed.name)

                os_log(.info, log: log, "Feed %{public}@ downloaded: %d bytes", feed.name, data.count)
                results.append((name: feed.name, data: text))

            } catch {
                os_log(.error, log: log, "Feed %{public}@ download failed: %{public}@", feed.name, error.localizedDescription)
                // Fall back to cache
                if let cached = readCachedFeed(filename: feed.filename) {
                    results.append((name: feed.name, data: cached))
                }
            }
        }

        return results
    }

    /// Load cached feeds from disk (for app launch without network).
    func loadCachedFeeds() -> [(name: String, data: String)] {
        var results: [(name: String, data: String)] = []

        for feed in Self.feeds {
            if let data = readCachedFeed(filename: feed.filename) {
                results.append((name: feed.name, data: data))
            }
        }

        return results
    }

    /// Get the last update timestamp for a feed.
    func lastUpdated(feed: String) -> Date? {
        let defaults = UserDefaults(suiteName: AppGroupConfig.groupIdentifier)
        let ts = defaults?.double(forKey: Self.lastUpdatedKeyPrefix + feed) ?? 0
        guard ts > 0 else { return nil }
        return Date(timeIntervalSince1970: ts)
    }

    // MARK: - Private

    private func feedPath(filename: String) -> URL {
        AppGroupConfig.containerURL.appendingPathComponent(filename)
    }

    private func readCachedFeed(filename: String) -> String? {
        let path = feedPath(filename: filename)
        guard FileManager.default.fileExists(atPath: path.path) else { return nil }
        return try? String(contentsOf: path, encoding: .utf8)
    }
}
