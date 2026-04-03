import SwiftUI

struct DomainListView: View {
    @StateObject private var viewModel = DomainListViewModel()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 0) {
                    modePicker

                    switch viewModel.viewMode {
                    case .sites:
                        sitesContent
                    case .allDomains:
                        domainsContent
                    }
                }
                .padding(.bottom, 24)
            }
            .background(Theme.pageBackground)
            .navigationTitle("Domains")
            .searchable(text: $viewModel.searchText, prompt: "Search domains")
            .navigationDestination(for: DomainRecord.self) { domain in
                DomainDetailView(domain: domain)
            }
            .navigationDestination(for: SiteRecord.self) { site in
                SiteDetailView(site: site)
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    sortMenuButton
                }
            }
            .refreshable {
                viewModel.refresh()
            }
            .sensoryFeedback(.selection, trigger: viewModel.sortOption)
        }
    }

    // MARK: - Mode Picker

    private var modePicker: some View {
        Picker("View", selection: $viewModel.viewMode) {
            ForEach(DomainListViewModel.ViewMode.allCases, id: \.self) { mode in
                Text(mode.rawValue).tag(mode)
            }
        }
        .pickerStyle(.segmented)
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    // MARK: - Sort Menu

    private var sortMenuButton: some View {
        Menu {
            Picker("Sort by", selection: Binding(
                get: { viewModel.sortOption },
                set: { newValue in
                    withAnimation(.snappy(duration: 0.3)) {
                        viewModel.sortBy(newValue)
                    }
                }
            )) {
                ForEach(DomainListViewModel.SortOption.allCases) { option in
                    Label(option.rawValue, systemImage: sortIcon(for: option))
                        .tag(option)
                }
            }
        } label: {
            HStack(spacing: 4) {
                Image(systemName: sortIcon(for: viewModel.sortOption))
                    .font(.system(size: 12, weight: .semibold))
                    .symbolEffect(.bounce, value: viewModel.sortOption)
                Text(viewModel.sortOption.rawValue)
                    .font(.system(size: 13, weight: .medium))
            }
            .foregroundStyle(Theme.accent)
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(Theme.accent.opacity(0.12), in: Capsule())
        }
    }

    private func sortIcon(for option: DomainListViewModel.SortOption) -> String {
        switch option {
        case .recent: return "clock"
        case .visitCount: return "flame.fill"
        case .alphabetical: return "textformat.abc"
        }
    }

    // MARK: - Sites Content

    @ViewBuilder
    private var sitesContent: some View {
        if viewModel.groupedSites.isEmpty {
            emptyState(
                title: "No Sites Found",
                message: viewModel.searchText.isEmpty
                    ? "Connect the VPN to start seeing sites."
                    : "No sites match your search."
            )
        } else {
            LazyVStack(spacing: 20) {
                ForEach(viewModel.groupedSites) { group in
                    siteSection(group)
                }
            }
        }
    }

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

    // MARK: - Domains Content

    @ViewBuilder
    private var domainsContent: some View {
        if viewModel.groupedDomains.isEmpty {
            emptyState(
                title: "No Domains Found",
                message: viewModel.searchText.isEmpty
                    ? "Connect the VPN to start seeing domains."
                    : "No domains match your search."
            )
        } else {
            LazyVStack(spacing: 20) {
                ForEach(viewModel.groupedDomains) { group in
                    domainSection(group)
                }
            }
        }
    }

    private func domainSection(_ group: DomainListViewModel.DomainGroup) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            sectionHeader(title: group.key, count: group.domains.count)

            VStack(spacing: 0) {
                ForEach(Array(group.domains.enumerated()), id: \.element.id) { index, domain in
                    if index > 0 {
                        Divider().padding(.leading, 62)
                    }
                    NavigationLink(value: domain) {
                        DomainRowView(domain: domain)
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

    // MARK: - Empty State

    private func emptyState(title: String, message: String) -> some View {
        ContentUnavailableView(
            title,
            systemImage: "globe",
            description: Text(message)
        )
        .frame(minHeight: 400)
    }
}

#Preview {
    DomainListView()
}
