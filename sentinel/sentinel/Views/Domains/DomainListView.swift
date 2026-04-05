import SwiftUI

struct DomainListView: View {
    @StateObject private var viewModel = DomainListViewModel()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 0) {
                    if viewModel.groupedSites.isEmpty {
                        ContentUnavailableView(
                            "No Sites Found",
                            systemImage: "globe",
                            description: Text(
                                viewModel.searchText.isEmpty
                                    ? "Connect the VPN to start seeing sites."
                                    : "No sites match your search."
                            )
                        )
                        .frame(minHeight: 400)
                    } else {
                        LazyVStack(spacing: 20) {
                            ForEach(viewModel.groupedSites) { group in
                                siteSection(group)
                            }
                        }
                    }
                }
                .padding(.bottom, 24)
            }
            .background(Theme.pageBackground)
            .navigationTitle("Domains")
            .searchable(text: $viewModel.searchText, prompt: "Search domains")
            .navigationDestination(for: SiteRecord.self) { site in
                SiteDetailView(site: site)
            }
            .refreshable {
                viewModel.refresh()
            }
        }
    }

    // MARK: - Site Section

    private func siteSection(_ group: DomainListViewModel.SiteGroup) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader(title: group.key, count: group.sites.count)

            VStack(spacing: 0) {
                ForEach(Array(group.sites.enumerated()), id: \.element.id) { index, site in
                    if index > 0 {
                        Divider().padding(.leading, 62)
                    }
                    NavigationLink(value: site) {
                        SiteRowView(site: site)
                            .padding(.horizontal, 14)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.vertical, 4)
            .background(Theme.cardBackground)
            .clipShape(RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous))
            .shadow(color: Theme.cardShadow, radius: 8, y: 2)
        }
        .padding(.horizontal, 16)
    }

    // MARK: - Section Header

    private func sectionHeader(title: String, count: Int) -> some View {
        HStack(spacing: 8) {
            Text(title.uppercased())
                .font(.system(size: 13, weight: .semibold, design: .rounded))
                .foregroundStyle(.secondary)
                .tracking(0.8)

            Text("\(count)")
                .font(.system(size: 11, weight: .bold, design: .rounded))
                .foregroundStyle(.white)
                .frame(minWidth: 20, minHeight: 20)
                .padding(.horizontal, count > 99 ? 4 : 0)
                .background(Theme.accent.opacity(0.6), in: Capsule())
                .contentTransition(.numericText())

            Spacer()
        }
        .padding(.horizontal, 4)
    }
}

#Preview {
    DomainListView()
}
