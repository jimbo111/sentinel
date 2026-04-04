import SwiftUI

struct DomainDetailView: View {
    let domain: DomainRecord

    @State private var visits: [VisitRecord] = []
    @State private var ips: [(ip: String, firstSeen: Int64, lastSeen: Int64)] = []
    @State private var queryTypes: [(queryType: Int, name: String, count: Int, lastSeen: Int64)] = []
    @State private var isLoading = true

    var body: some View {
        ScrollView {
            VStack(spacing: 12) {
                // Header card
                VStack(spacing: 10) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 16)
                            .fill(Theme.accent.opacity(0.1))
                            .frame(width: 56, height: 56)

                        Image(systemName: "globe")
                            .font(.system(size: 24, weight: .medium))
                            .foregroundColor(Theme.accent)
                    }

                    Text(domain.domain)
                        .font(.title2.bold())
                        .textSelection(.enabled)
                }
                .frame(maxWidth: .infinity)
                .padding(20)
                .cardStyle()

                // Overview card — includes TLS version row
                VStack(alignment: .leading, spacing: 12) {
                    SectionHeader(title: "Overview")

                    DetailRow(label: "Total Visits", value: "\(domain.visitCount)")
                    Divider()
                    DetailRow(label: "First Seen", value: domain.firstSeenFormatted)
                    Divider()
                    DetailRow(label: "Last Seen", value: domain.lastSeenFormatted)
                    Divider()
                    DetailRow(label: "Detection Source", value: domain.source)
                    if let tlsVersion = domain.tlsVersion {
                        Divider()
                        DetailRow(label: "TLS Version", value: tlsVersion)
                    }
                }
                .padding(16)
                .cardStyle()

                // Data Volume card
                if domain.totalBytes > 0 {
                    VStack(alignment: .leading, spacing: 12) {
                        SectionHeader(title: "Data Volume")

                        DetailRow(
                            label: "Data In",
                            value: ByteCountFormatter.string(fromByteCount: domain.bytesIn, countStyle: .binary)
                        )
                        Divider()
                        DetailRow(
                            label: "Data Out",
                            value: ByteCountFormatter.string(fromByteCount: domain.bytesOut, countStyle: .binary)
                        )
                        Divider()
                        DetailRow(label: "Total", value: domain.formattedDataVolume)
                    }
                    .padding(16)
                    .cardStyle()
                }

                // IP Addresses card
                if !ips.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        SectionHeader(title: "IP Addresses", count: ips.count)

                        ForEach(Array(ips.enumerated()), id: \.offset) { index, entry in
                            HStack(spacing: 12) {
                                Image(systemName: "network")
                                    .foregroundColor(Theme.accent)
                                    .frame(width: 40, height: 40)
                                    .background(Theme.accent.opacity(0.1))
                                    .cornerRadius(12)

                                Text(entry.ip)
                                    .font(.subheadline.monospacedDigit())
                                    .textSelection(.enabled)

                                Spacer()

                                Text(relativeTime(ms: entry.lastSeen))
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }

                            if index < ips.count - 1 {
                                Divider()
                            }
                        }
                    }
                    .padding(16)
                    .cardStyle()
                }

                // DNS Record Types card
                if !queryTypes.isEmpty {
                    VStack(alignment: .leading, spacing: 12) {
                        SectionHeader(title: "DNS Record Types", count: queryTypes.count)

                        ForEach(Array(queryTypes.enumerated()), id: \.offset) { index, entry in
                            HStack {
                                Text(entry.name.isEmpty ? "Type \(entry.queryType)" : entry.name)
                                    .foregroundColor(.secondary)
                                Spacer()
                                Text("\(entry.count)x")
                                    .font(.subheadline.monospacedDigit().weight(.semibold))
                                    .foregroundColor(.primary)
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 5)
                                    .background(Color(.systemGray5))
                                    .cornerRadius(10)
                            }

                            if index < queryTypes.count - 1 {
                                Divider()
                            }
                        }
                    }
                    .padding(16)
                    .cardStyle()
                }

                // Recent visits card
                VStack(alignment: .leading, spacing: 12) {
                    SectionHeader(title: "Recent Visits", count: visits.count)

                    if isLoading {
                        HStack {
                            Spacer()
                            ProgressView()
                            Spacer()
                        }
                        .padding(.vertical, 8)
                    } else if visits.isEmpty {
                        Text("No visit history recorded yet.")
                            .foregroundColor(.secondary)
                            .font(.subheadline)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.vertical, 4)
                    } else {
                        ForEach(Array(visits.enumerated()), id: \.element.id) { index, visit in
                            HStack(spacing: 12) {
                                Image(systemName: "clock")
                                    .foregroundColor(.secondary)
                                    .frame(width: 40, height: 40)
                                    .background(Color(.systemGray6))
                                    .cornerRadius(12)

                                VStack(alignment: .leading, spacing: 2) {
                                    Text(formattedDate(visit.date))
                                        .font(.subheadline)
                                }
                                Spacer()

                                Text(visit.source)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }

                            if index < visits.count - 1 {
                                Divider()
                            }
                        }
                    }
                }
                .padding(16)
                .cardStyle()
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 20)
        }
        .background(Theme.pageBackground)
        .navigationTitle(domain.domain)
        .navigationBarTitleDisplayMode(.inline)
        .task {
            await loadAllData()
        }
    }

    private func loadAllData() async {
        let domainName = domain.domain
        let domainId = domain.id

        async let fetchedVisits = Task.detached(priority: .userInitiated) {
            DatabaseReader.shared.visits(forDomainId: domainId)
        }.value
        async let fetchedIPs = Task.detached(priority: .userInitiated) {
            DatabaseReader.shared.ipsForDomain(domainName)
        }.value
        async let fetchedQueryTypes = Task.detached(priority: .userInitiated) {
            DatabaseReader.shared.queryTypesForDomain(domainName)
        }.value

        visits = await fetchedVisits
        ips = await fetchedIPs
        queryTypes = await fetchedQueryTypes
        isLoading = false
    }

    private static let relativeDateFormatter: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter
    }()

    private func relativeTime(ms: Int64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(ms) / 1000)
        return Self.relativeDateFormatter.localizedString(for: date, relativeTo: Date())
    }

    private static let visitDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()

    private func formattedDate(_ date: Date) -> String {
        Self.visitDateFormatter.string(from: date)
    }
}

struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .foregroundColor(.secondary)
            Spacer()
            Text(value)
                .fontWeight(.medium)
        }
    }
}

#Preview {
    NavigationStack {
        DomainDetailView(domain: DomainRecord(
            id: 1,
            domain: "apple.com",
            firstSeenMs: Int64((Date().timeIntervalSince1970 - 86400 * 5) * 1000),
            lastSeenMs: Int64((Date().timeIntervalSince1970 - 3600) * 1000),
            visitCount: 42,
            source: "DNS",
            siteDomain: nil,
            tlsVersion: "TLSv1.3",
            bytesIn: 1_245_184,
            bytesOut: 310_272
        ))
    }
}
