import Foundation
import Combine

@MainActor
class DomainListViewModel: ObservableObject {

    struct SiteGroup: Identifiable {
        let key: String
        let sites: [SiteRecord]
        var id: String { key }
    }

    @Published var groupedSites: [SiteGroup] = []
    @Published var searchText: String = ""

    private var cancellables = Set<AnyCancellable>()
    private let notificationListener = DarwinNotificationListener(
        name: AppGroupConfig.newDomainsNotification
    )
    private var lastFetchTime: CFAbsoluteTime = 0
    private static let fetchThrottleSeconds: CFAbsoluteTime = 1.0

    init() {
        fetchSites()

        // Re-fetch when the user types.
        $searchText
            .debounce(for: .milliseconds(200), scheduler: RunLoop.main)
            .sink { [weak self] _ in
                self?.fetchSites()
            }
            .store(in: &cancellables)

        // Listen for Darwin notifications from the packet tunnel extension.
        notificationListener.startListening { [weak self] in
            Task { @MainActor [weak self] in
                guard let self else { return }
                let now = CFAbsoluteTimeGetCurrent()
                guard now - self.lastFetchTime >= Self.fetchThrottleSeconds else { return }
                self.lastFetchTime = now
                self.fetchSites()
            }
        }
    }

    func refresh() {
        fetchSites()
    }

    // MARK: - Data Fetching

    private func fetchSites() {
        let capturedSearch = searchText

        Task {
            let sites = await Task.detached(priority: .userInitiated) {
                if capturedSearch.isEmpty {
                    return DatabaseReader.shared.recentSites()
                } else {
                    return DatabaseReader.shared.searchSites(query: capturedSearch)
                }
            }.value

            guard searchText == capturedSearch else { return }
            groupedSites = groupSitesByDate(sites)
        }
    }

    // MARK: - Grouping

    private func groupSitesByDate(_ sites: [SiteRecord]) -> [SiteGroup] {
        let calendar = Calendar.current

        var todaySites: [SiteRecord] = []
        var yesterdaySites: [SiteRecord] = []
        var earlierSites: [SiteRecord] = []

        for site in sites {
            if calendar.isDateInToday(site.lastSeenDate) {
                todaySites.append(site)
            } else if calendar.isDateInYesterday(site.lastSeenDate) {
                yesterdaySites.append(site)
            } else {
                earlierSites.append(site)
            }
        }

        var groups: [SiteGroup] = []
        if !todaySites.isEmpty {
            groups.append(SiteGroup(key: "Today", sites: todaySites))
        }
        if !yesterdaySites.isEmpty {
            groups.append(SiteGroup(key: "Yesterday", sites: yesterdaySites))
        }
        if !earlierSites.isEmpty {
            groups.append(SiteGroup(key: "Earlier", sites: earlierSites))
        }
        return groups
    }
}
