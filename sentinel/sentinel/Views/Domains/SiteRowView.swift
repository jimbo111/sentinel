import SwiftUI

struct SiteRowView: View {
    let site: SiteRecord

    private var categoryInfo: (key: String, label: String, icon: String)? {
        CategoriesService.shared.categorize(site.siteDomain)
    }

    private var categoryColor: Color {
        if let info = categoryInfo {
            return Theme.categoryColors[info.key] ?? Theme.accent
        }
        return Theme.accent
    }

    private var iconName: String {
        categoryInfo?.icon ?? "globe"
    }

    private var categoryLabel: String? {
        categoryInfo?.label
    }

    var body: some View {
        HStack(spacing: 12) {
            // Left: category icon on gradient background
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

                Image(systemName: iconName)
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(.white)
                    .accessibilityHidden(true)
            }

            // Center: domain name + metadata row
            VStack(alignment: .leading, spacing: 4) {
                Text(site.siteDomain)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)

                HStack(spacing: 6) {
                    // Category pill badge
                    if let label = categoryLabel {
                        Text(label)
                            .font(.system(size: 10, weight: .medium))
                            .foregroundStyle(categoryColor)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(
                                Capsule()
                                    .fill(categoryColor.opacity(0.1))
                            )
                    }

                    Text("\(site.domainCount) domain\(site.domainCount == 1 ? "" : "s")")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)

                    Text("\u{00B7}")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)

                    Text(site.relativeTimeString)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
            }

            Spacer(minLength: 4)

            // Right: visit count + chevron
            HStack(spacing: 6) {
                Text("\(site.totalVisits)")
                    .font(.system(size: 16, weight: .bold, design: .rounded))
                    .foregroundStyle(categoryColor)

                Image(systemName: "chevron.right")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Color(.tertiaryLabel))
            }
        }
        .padding(.vertical, 10)
    }
}

#Preview {
    let now = Date()
    VStack(spacing: 0) {
        SiteRowView(site: SiteRecord(
            siteDomain: "youtube.com", domainCount: 5, totalVisits: 142,
            firstSeenMs: Int64((now.timeIntervalSince1970 - 86400) * 1000),
            lastSeenMs: Int64((now.timeIntervalSince1970 - 3600) * 1000),
            totalBytesIn: 0, totalBytesOut: 0
        ))
        .padding(.horizontal, 14)
        Divider().padding(.leading, 62)
        SiteRowView(site: SiteRecord(
            siteDomain: "reddit.com", domainCount: 12, totalVisits: 87,
            firstSeenMs: Int64((now.timeIntervalSince1970 - 86400 * 3) * 1000),
            lastSeenMs: Int64((now.timeIntervalSince1970 - 600) * 1000),
            totalBytesIn: 0, totalBytesOut: 0
        ))
        .padding(.horizontal, 14)
        Divider().padding(.leading, 62)
        SiteRowView(site: SiteRecord(
            siteDomain: "unknown-tracker.io", domainCount: 1, totalVisits: 3,
            firstSeenMs: Int64((now.timeIntervalSince1970 - 86400) * 1000),
            lastSeenMs: Int64((now.timeIntervalSince1970 - 300) * 1000),
            totalBytesIn: 0, totalBytesOut: 0
        ))
        .padding(.horizontal, 14)
    }
    .padding(.vertical, 4)
    .cardStyle()
    .padding(16)
    .background(Theme.pageBackground)
}
