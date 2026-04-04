import Foundation

struct SiteRecord: Identifiable, Hashable, Sendable {
    let siteDomain: String
    let domainCount: Int
    let totalVisits: Int
    let firstSeenMs: Int64
    let lastSeenMs: Int64
    let totalBytesIn: Int64
    let totalBytesOut: Int64

    var formattedDataVolume: String {
        ByteCountFormatter.string(fromByteCount: totalBytesIn + totalBytesOut, countStyle: .binary)
    }

    var id: String { siteDomain }

    var lastSeenDate: Date {
        Date(timeIntervalSince1970: TimeInterval(lastSeenMs) / 1000)
    }

    var firstSeenDate: Date {
        Date(timeIntervalSince1970: TimeInterval(firstSeenMs) / 1000)
    }

    private static let relativeDateFormatter: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter
    }()

    private static let mediumDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()

    var relativeTimeString: String {
        Self.relativeDateFormatter.localizedString(for: lastSeenDate, relativeTo: Date())
    }

    var firstSeenFormatted: String {
        Self.mediumDateFormatter.string(from: firstSeenDate)
    }

    var lastSeenFormatted: String {
        Self.mediumDateFormatter.string(from: lastSeenDate)
    }
}
