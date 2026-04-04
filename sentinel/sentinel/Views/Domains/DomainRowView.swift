import SwiftUI

struct DomainRowView: View {
    let domain: DomainRecord

    private var categoryColor: Color {
        if let site = domain.siteDomain {
            return Theme.colorForDomain(site)
        }
        return Theme.accent
    }

    var body: some View {
        HStack(spacing: 12) {
            // Left: globe icon on category-colored gradient
            ZStack {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(
                        LinearGradient(
                            colors: [categoryColor, categoryColor.opacity(0.7)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .frame(width: 36, height: 36)

                Image(systemName: "globe")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.white)
            }

            // Center: domain name + metadata row
            VStack(alignment: .leading, spacing: 4) {
                Text(domain.domain)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)

                HStack(spacing: 5) {
                    // Source badge (DNS = green, other = blue)
                    sourceBadge

                    // Parent site name in category color (compresses first on narrow screens)
                    if let site = domain.siteDomain {
                        Text(site)
                            .font(.system(size: 11, weight: .medium))
                            .foregroundStyle(categoryColor)
                            .lineLimit(1)
                            .layoutPriority(-1)
                    }

                    // TLS version pill
                    if let tls = domain.tlsVersion, !tls.isEmpty {
                        Text(tls)
                            .font(.system(size: 10, weight: .medium))
                            .foregroundStyle(Color(.tertiaryLabel))
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1.5)
                            .background(
                                Capsule()
                                    .fill(Color(.systemGray5))
                            )
                    }

                    Text(domain.relativeTimeString)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .layoutPriority(1)
                }
            }

            Spacer(minLength: 4)

            // Right: visit count + chevron
            HStack(spacing: 6) {
                Text("\(domain.visitCount)")
                    .font(.system(size: 16, weight: .bold, design: .rounded))
                    .foregroundStyle(categoryColor)

                Image(systemName: "chevron.right")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Color(.tertiaryLabel))
            }
        }
        .padding(.vertical, 10)
    }

    private var sourceBadge: some View {
        Text(domain.source)
            .font(.system(size: 10, weight: .bold))
            .foregroundStyle(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(
                Capsule()
                    .fill(domain.source == "DNS" ? Color.green : Color.blue)
            )
    }
}

#Preview {
    let now = Date()
    VStack(spacing: 0) {
        DomainRowView(domain: DomainRecord(
            id: 1, domain: "i.ytimg.com",
            firstSeenMs: Int64((now.timeIntervalSince1970 - 86400) * 1000),
            lastSeenMs: Int64((now.timeIntervalSince1970 - 600) * 1000),
            visitCount: 84, source: "DNS", siteDomain: "youtube.com",
            tlsVersion: "TLSv1.3", bytesIn: 0, bytesOut: 0
        ))
        .padding(.horizontal, 14)
        Divider().padding(.leading, 62)
        DomainRowView(domain: DomainRecord(
            id: 2, domain: "static.reddit.com",
            firstSeenMs: Int64((now.timeIntervalSince1970 - 86400) * 1000),
            lastSeenMs: Int64((now.timeIntervalSince1970 - 120) * 1000),
            visitCount: 37, source: "DNS", siteDomain: "reddit.com",
            tlsVersion: nil, bytesIn: 0, bytesOut: 0
        ))
        .padding(.horizontal, 14)
        Divider().padding(.leading, 62)
        DomainRowView(domain: DomainRecord(
            id: 3, domain: "telemetry.unknown.io",
            firstSeenMs: Int64((now.timeIntervalSince1970 - 86400 * 5) * 1000),
            lastSeenMs: Int64((now.timeIntervalSince1970 - 60) * 1000),
            visitCount: 5, source: "OTHER", siteDomain: nil,
            tlsVersion: nil, bytesIn: 0, bytesOut: 0
        ))
        .padding(.horizontal, 14)
    }
    .padding(.vertical, 4)
    .cardStyle()
    .padding(16)
    .background(Theme.pageBackground)
}
