import SwiftUI

struct SiteDetailView: View {
    let site: SiteRecord

    @State private var domains: [DomainRecord] = []
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
                            .accessibilityHidden(true)
                    }

                    Text(site.siteDomain)
                        .font(.title2.bold())
                        .textSelection(.enabled)
                }
                .frame(maxWidth: .infinity)
                .padding(20)
                .cardStyle()

                // Overview card
                VStack(alignment: .leading, spacing: 12) {
                    SectionHeader(title: "Overview")

                    DetailRow(label: "Total Visits", value: "\(site.totalVisits)")
                    Divider()
                    DetailRow(label: "Domains", value: "\(site.domainCount)")
                    Divider()
                    DetailRow(label: "First Seen", value: site.firstSeenFormatted)
                    Divider()
                    DetailRow(label: "Last Seen", value: site.lastSeenFormatted)
                    if site.totalBytesIn + site.totalBytesOut > 0 {
                        Divider()
                        DetailRow(label: "Data Volume", value: site.formattedDataVolume)
                    }
                }
                .padding(16)
                .cardStyle()

                // Associated domains card
                VStack(alignment: .leading, spacing: 12) {
                    SectionHeader(title: "Associated Domains", count: domains.count)

                    if isLoading {
                        HStack {
                            Spacer()
                            ProgressView()
                            Spacer()
                        }
                        .padding(.vertical, 8)
                    } else if domains.isEmpty {
                        Text("No associated domains found.")
                            .foregroundColor(.secondary)
                            .font(.subheadline)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.vertical, 4)
                    } else {
                        ForEach(Array(domains.enumerated()), id: \.element.id) { index, domain in
                            NavigationLink(value: domain) {
                                DomainRowView(domain: domain)
                            }
                            .buttonStyle(.plain)

                            if index < domains.count - 1 {
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
        .navigationTitle(site.siteDomain)
        .navigationBarTitleDisplayMode(.inline)
        .navigationDestination(for: DomainRecord.self) { domain in
            DomainDetailView(domain: domain)
        }
        .task {
            await loadDomains()
        }
    }

    private func loadDomains() async {
        let siteDomain = site.siteDomain
        let fetched = await Task.detached(priority: .userInitiated) {
            DatabaseReader.shared.domainsForSite(siteDomain)
        }.value

        domains = fetched
        isLoading = false
    }
}

#Preview {
    NavigationStack {
        SiteDetailView(site: SiteRecord(
            siteDomain: "youtube.com",
            domainCount: 5,
            totalVisits: 42,
            firstSeenMs: Int64((Date().timeIntervalSince1970 - 86400 * 5) * 1000),
            lastSeenMs: Int64((Date().timeIntervalSince1970 - 3600) * 1000),
            totalBytesIn: 0,
            totalBytesOut: 0
        ))
    }
}
