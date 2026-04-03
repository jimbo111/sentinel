import SwiftUI

/// A single row in the recent threats list.
struct ThreatRowView: View {
    let threat: ThreatRecord

    var body: some View {
        HStack(spacing: 12) {
            // Threat type icon
            ZStack {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(
                        LinearGradient(
                            colors: [threat.threatColor, threat.threatColor.opacity(0.7)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .frame(width: 36, height: 36)

                Image(systemName: threat.threatIcon)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.white)
            }

            // Domain + metadata
            VStack(alignment: .leading, spacing: 4) {
                Text(threat.domain)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .truncationMode(.middle)

                HStack(spacing: 5) {
                    // Threat type badge
                    Text(threat.threatTypeDisplay)
                        .font(.system(size: 10, weight: .bold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(threat.threatColor))

                    Text(threat.feedName)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)

                    Text(threat.relativeTimeString)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .layoutPriority(1)
                }
            }

            Spacer(minLength: 4)

            // Chevron
            Image(systemName: "chevron.right")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(Color(.tertiaryLabel))
        }
        .padding(.vertical, 10)
        .padding(.horizontal, 14)
    }
}

#Preview {
    let now = Date()
    VStack(spacing: 0) {
        ThreatRowView(threat: ThreatRecord(
            id: 1, domain: "phishing-bank.com", threatType: "phishing",
            feedName: "hagezi-pro", confidence: 0.95,
            timestampMs: Int64((now.timeIntervalSince1970 - 120) * 1000), dismissed: false
        ))
        Divider().padding(.leading, 62)
        ThreatRowView(threat: ThreatRecord(
            id: 2, domain: "malware-download.xyz", threatType: "malware",
            feedName: "urlhaus-malware", confidence: 0.99,
            timestampMs: Int64((now.timeIntervalSince1970 - 3600) * 1000), dismissed: false
        ))
        Divider().padding(.leading, 62)
        ThreatRowView(threat: ThreatRecord(
            id: 3, domain: "c2.evil-server.net", threatType: "command",
            feedName: "hagezi-pro", confidence: 0.87,
            timestampMs: Int64((now.timeIntervalSince1970 - 86400) * 1000), dismissed: false
        ))
    }
    .cardStyle()
    .padding(16)
    .background(Theme.pageBackground)
}
