import Foundation
import SwiftUI

struct ThreatRecord: Identifiable, Sendable {
    let id: Int64
    let domain: String
    let threatType: String
    let feedName: String
    let confidence: Double
    let timestampMs: Int64
    let dismissed: Bool

    var date: Date {
        Date(timeIntervalSince1970: TimeInterval(timestampMs) / 1000)
    }

    var threatTypeDisplay: String {
        switch threatType {
        case "phishing": return "Phishing"
        case "malware": return "Malware"
        case "command": return "C2 Server"
        case "tracking": return "Tracker"
        default: return "Unknown Threat"
        }
    }

    var threatIcon: String {
        switch threatType {
        case "phishing": return "exclamationmark.shield.fill"
        case "malware": return "ladybug.fill"
        case "command": return "antenna.radiowaves.left.and.right"
        case "tracking": return "eye.slash.fill"
        default: return "shield.slash.fill"
        }
    }

    var threatColor: Color {
        switch threatType {
        case "phishing": return Theme.threatRed
        case "malware": return Theme.threatRed
        case "command": return Theme.threatOrange
        case "tracking": return Theme.threatYellow
        default: return .gray
        }
    }

    // MARK: - Formatting

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
        Self.relativeDateFormatter.localizedString(for: date, relativeTo: Date())
    }

    var dateFormatted: String {
        Self.mediumDateFormatter.string(from: date)
    }

    var confidencePercent: String {
        "\(Int(confidence * 100))%"
    }
}
