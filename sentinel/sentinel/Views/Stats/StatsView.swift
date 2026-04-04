import SwiftUI
import Charts

// MARK: - Stats Tab Enum

enum StatsTab: String, CaseIterable {
    case overview = "Overview"
    case rankings = "Rankings"
    case categories = "Categories"
}

// MARK: - StatsView

struct StatsView: View {
    @StateObject private var viewModel = StatsViewModel()
    @State private var selectedTab: StatsTab = .overview
    @State private var sites: [SiteRecord] = []
    @State private var categories: [CategoriesService.CategoryResult] = []
    @State private var expandedCategory: String?

    private let categoryColors: [String: Color] = [
        "social_media": .blue,
        "shopping": .orange,
        "entertainment": .purple,
        "news": .red,
        "search": .green,
        "communication": .teal,
        "finance": .mint,
        "productivity": .indigo,
        "gaming": .pink,
        "education": .cyan,
        "food_delivery": .yellow,
        "health": Color(red: 0.9, green: 0.3, blue: 0.3),
        "travel": Color(red: 0.2, green: 0.6, blue: 0.9),
        "technology": .gray,
        "ai_tools": Color(red: 0.4, green: 0.3, blue: 0.9),
        "dating": Color(red: 0.95, green: 0.3, blue: 0.5),
        "sports": Color(red: 0.1, green: 0.7, blue: 0.4),
        "weather": Color(red: 0.3, green: 0.7, blue: 0.9),
        "government": Color(red: 0.2, green: 0.4, blue: 0.7),
        "transportation": Color(red: 0.95, green: 0.6, blue: 0.1),
        "uncategorized": Color(.systemGray3),
    ]

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                if viewModel.totalDomains == 0 && viewModel.totalVisits == 0 {
                    ScrollView {
                        ContentUnavailableView(
                            "No Stats Yet",
                            systemImage: "chart.bar",
                            description: Text("Connect the VPN to start seeing statistics.")
                        )
                        .frame(minHeight: 400)
                    }
                    .background(Theme.pageBackground)
                } else {
                    Picker("Stats", selection: $selectedTab) {
                        ForEach(StatsTab.allCases, id: \.self) { tab in
                            Text(tab.rawValue).tag(tab)
                        }
                    }
                    .pickerStyle(.segmented)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 8)

                    ScrollView {
                        switch selectedTab {
                        case .overview:
                            overviewTab
                        case .rankings:
                            rankingsTab
                        case .categories:
                            categoriesTab
                        }
                    }
                    .background(Theme.pageBackground)
                }
            }
            .background(Theme.pageBackground)
            .navigationTitle("Stats")
            .refreshable {
                viewModel.refresh()
                loadSitesAndCategories()
            }
            .task {
                loadSitesAndCategories()
            }
        }
    }

    private func loadSitesAndCategories() {
        let fetchedSites = DatabaseReader.shared.recentSites(limit: 100)
        sites = fetchedSites
        categories = CategoriesService.shared.categorizeSites(fetchedSites)
    }

    private func colorForSite(_ siteDomain: String) -> Color {
        if let cat = CategoriesService.shared.categorize(siteDomain) {
            return categoryColors[cat.key] ?? Theme.accent
        }
        return Theme.accent
    }

    // MARK: - Overview Tab

    private var overviewTab: some View {
        VStack(spacing: 16) {
            // Hero metrics with meaningful colors
            HStack(spacing: 12) {
                coloredMetricCard(value: "\(viewModel.totalDomains)", label: "Domains", color: .blue, icon: "globe")
                coloredMetricCard(value: viewModel.formattedVisits, label: "Visits", color: .purple, icon: "arrow.triangle.swap")
                coloredMetricCard(value: "\(viewModel.domainsToday)", label: "Today", color: .green, icon: "calendar")
            }
            .padding(.horizontal, 16)

            // Mini category distribution bar
            if !categories.isEmpty {
                let totalVisits = categories.reduce(0) { $0 + $1.totalVisits }
                VStack(alignment: .leading, spacing: 8) {
                    Text("Activity Breakdown")
                        .font(.caption.weight(.medium))
                        .foregroundColor(.secondary)

                    categoryDistributionBar(totalVisits: totalVisits)

                    // Top 3 category labels
                    HStack(spacing: 12) {
                        ForEach(categories.prefix(3), id: \.key) { cat in
                            let color = categoryColors[cat.key] ?? .gray
                            HStack(spacing: 4) {
                                Circle()
                                    .fill(color)
                                    .frame(width: 8, height: 8)
                                Text(cat.label)
                                    .font(.system(size: 11))
                                    .foregroundColor(.secondary)
                            }
                        }
                        Spacer()
                    }
                }
                .padding(14)
                .cardStyle()
                .padding(.horizontal, 16)
            }

            // 7-day chart with colored bars
            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(title: "Activity")

                Chart(viewModel.dailyDomainCounts) { item in
                    BarMark(
                        x: .value("Day", item.dayLabel),
                        y: .value("Count", item.count)
                    )
                    .foregroundStyle(
                        item.count == viewModel.dailyDomainCounts.map(\.count).max()
                            ? Theme.accent.gradient
                            : Color.secondary.opacity(0.4).gradient
                    )
                    .cornerRadius(6)
                }
                .frame(height: 200)
                .chartYAxis {
                    AxisMarks(position: .leading)
                }
            }
            .padding(20)
            .cardStyle()
            .padding(.horizontal, 16)

            // Insight card
            insightCard
                .padding(.horizontal, 16)
        }
        .padding(.top, 8)
        .padding(.bottom, 20)
    }

    private func coloredMetricCard(value: String, label: String, color: Color, icon: String) -> some View {
        VStack(spacing: 6) {
            Image(systemName: icon)
                .font(.caption)
                .foregroundColor(color)

            Text(value)
                .font(.system(size: 22, weight: .bold, design: .rounded))

            Text(label)
                .font(.system(size: 11))
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 14)
        .background(color.opacity(0.08))
        .cornerRadius(12)
        .overlay(
            RoundedRectangle(cornerRadius: 12)
                .stroke(color.opacity(0.15), lineWidth: 1)
        )
    }

    private var insightCard: some View {
        Group {
            if let bestDay = viewModel.dailyDomainCounts.max(by: { $0.count < $1.count }),
               bestDay.count > 0 {
                HStack(spacing: 10) {
                    Image(systemName: "lightbulb.fill")
                        .foregroundColor(.yellow)
                        .font(.body)

                    Text("Most active: **\(bestDay.dayLabel)** with \(bestDay.count) unique domains")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(14)
                .cardStyle()
            }
        }
    }

    // MARK: - Rankings Tab

    private var rankingsTab: some View {
        VStack(spacing: 16) {
            // Top Sites
            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(title: "Top Sites", count: min(sites.count, 10))
                    .padding(.horizontal, 16)

                let maxSiteVisits = sites.prefix(10).map(\.totalVisits).max() ?? 1

                ForEach(Array(sites.prefix(10).enumerated()), id: \.element.id) { index, site in
                    let proportion = maxSiteVisits > 0 ? CGFloat(site.totalVisits) / CGFloat(maxSiteVisits) : 0
                    let category = CategoriesService.shared.categorize(site.siteDomain)
                    let color = colorForSite(site.siteDomain)

                    VStack(alignment: .leading, spacing: 8) {
                        HStack(alignment: .firstTextBaseline) {
                            Text("\(index + 1)")
                                .font(.system(size: 16, weight: .bold, design: .rounded))
                                .foregroundColor(.white)
                                .frame(width: 26, height: 26)
                                .background(color)
                                .clipShape(RoundedRectangle(cornerRadius: 8))

                            Text(site.siteDomain)
                                .font(.system(size: 15, weight: .semibold))
                                .lineLimit(1)
                                .truncationMode(.middle)

                            Spacer()

                            Text("\(site.totalVisits)")
                                .font(.system(size: 15, weight: .bold, design: .rounded))
                                .foregroundColor(color)
                        }

                        // Colored progress bar
                        GeometryReader { geo in
                            ZStack(alignment: .leading) {
                                RoundedRectangle(cornerRadius: 4)
                                    .fill(color.opacity(0.12))
                                    .frame(height: 6)

                                RoundedRectangle(cornerRadius: 4)
                                    .fill(color.gradient)
                                    .frame(width: max(geo.size.width * proportion, 4), height: 6)
                            }
                        }
                        .frame(height: 6)

                        // Category badge + domain count
                        HStack(spacing: 6) {
                            if let cat = category {
                                Text(cat.label)
                                    .font(.system(size: 11, weight: .medium))
                                    .foregroundColor(color)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 3)
                                    .background(color.opacity(0.1))
                                    .cornerRadius(6)
                            }

                            Text("\(site.domainCount) domain\(site.domainCount == 1 ? "" : "s")")
                                .font(.system(size: 11))
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(14)
                    .cardStyle()
                    .padding(.horizontal, 16)
                }
            }

            // Top Raw Domains
            VStack(alignment: .leading, spacing: 12) {
                SectionHeader(title: "Top Domains")
                    .padding(.horizontal, 16)

                VStack(spacing: 0) {
                    ForEach(Array(viewModel.topDomains.enumerated()), id: \.element.id) { index, domain in
                        if index > 0 {
                            Divider().padding(.horizontal, 14)
                        }

                        let color = colorForSite(domain.domain)

                        HStack(spacing: 12) {
                            Text("\(index + 1)")
                                .font(.system(size: 13, weight: .bold, design: .rounded))
                                .foregroundColor(.white)
                                .frame(width: 24, height: 24)
                                .background(color)
                                .clipShape(RoundedRectangle(cornerRadius: 6))

                            Text(domain.domain)
                                .font(.subheadline)
                                .lineLimit(1)
                                .truncationMode(.middle)

                            Spacer()

                            Text("\(domain.visitCount)")
                                .font(.subheadline.monospacedDigit().weight(.medium))
                                .foregroundColor(.secondary)
                        }
                        .padding(.horizontal, 14)
                        .padding(.vertical, 10)
                    }
                }
                .cardStyle()
                .padding(.horizontal, 16)
            }
        }
        .padding(.top, 8)
        .padding(.bottom, 20)
    }

    // MARK: - Categories Tab

    private var categoriesTab: some View {
        VStack(spacing: 16) {
            if categories.isEmpty {
                ContentUnavailableView(
                    "No Categories Yet",
                    systemImage: "square.grid.2x2",
                    description: Text("Browse with Sentinel connected to see your activity breakdown.")
                )
                .frame(minHeight: 300)
            } else {
                let totalVisits = categories.reduce(0) { $0 + $1.totalVisits }
                let maxCategoryVisits = categories.map(\.totalVisits).max() ?? 1

                categoryDistributionBar(totalVisits: totalVisits)
                    .padding(.horizontal, 16)

                ForEach(categories, id: \.key) { cat in
                    let color = categoryColors[cat.key] ?? .gray
                    let percentage = totalVisits > 0
                        ? Int(round(Double(cat.totalVisits) / Double(totalVisits) * 100))
                        : 0
                    let proportion = maxCategoryVisits > 0
                        ? CGFloat(cat.totalVisits) / CGFloat(maxCategoryVisits)
                        : 0
                    let isExpanded = expandedCategory == cat.key

                    VStack(spacing: 0) {
                        // Category card content
                        VStack(alignment: .leading, spacing: 10) {
                            HStack(spacing: 12) {
                                Image(systemName: cat.icon)
                                    .font(.body.weight(.medium))
                                    .foregroundColor(color)
                                    .frame(width: 36, height: 36)
                                    .background(color.opacity(0.12))
                                    .clipShape(Circle())

                                VStack(alignment: .leading, spacing: 2) {
                                    Text(cat.label)
                                        .font(.system(size: 16, weight: .semibold))

                                    Text("\(cat.siteCount) site\(cat.siteCount == 1 ? "" : "s") \u{00B7} \(cat.totalVisits) visit\(cat.totalVisits == 1 ? "" : "s")")
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }

                                Spacer()

                                Text("\(percentage)%")
                                    .font(.system(size: 20, weight: .bold, design: .rounded))
                                    .foregroundColor(color)

                                Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundColor(.secondary)
                            }

                            // Progress bar
                            GeometryReader { geo in
                                ZStack(alignment: .leading) {
                                    RoundedRectangle(cornerRadius: 4)
                                        .fill(color.opacity(0.15))
                                        .frame(height: 8)

                                    RoundedRectangle(cornerRadius: 4)
                                        .fill(color.gradient)
                                        .frame(width: max(geo.size.width * proportion, 4), height: 8)
                                }
                            }
                            .frame(height: 8)
                        }
                        .padding(14)

                        // Expanded sites list
                        if isExpanded {
                            let categorySites = sites.filter {
                                CategoriesService.shared.categorize($0.siteDomain)?.key == cat.key
                            }

                            if !categorySites.isEmpty {
                                Divider().padding(.horizontal, 14)

                                VStack(spacing: 0) {
                                    ForEach(Array(categorySites.enumerated()), id: \.element.id) { index, site in
                                        if index > 0 {
                                            Divider().padding(.leading, 46)
                                        }

                                        HStack(spacing: 10) {
                                            Image(systemName: "globe")
                                                .font(.system(size: 12))
                                                .foregroundColor(color)
                                                .frame(width: 28, height: 28)
                                                .background(color.opacity(0.08))
                                                .cornerRadius(8)

                                            Text(site.siteDomain)
                                                .font(.system(size: 14))
                                                .lineLimit(1)

                                            Spacer()

                                            Text("\(site.totalVisits)")
                                                .font(.system(size: 13, design: .rounded).weight(.medium))
                                                .foregroundColor(.secondary)
                                        }
                                        .padding(.horizontal, 14)
                                        .padding(.vertical, 8)
                                    }
                                }
                                .transition(.opacity.combined(with: .move(edge: .top)))
                            }
                        }
                    }
                    .cardStyle()
                    .contentShape(Rectangle())
                    .onTapGesture {
                        withAnimation(.spring(response: 0.3, dampingFraction: 0.8)) {
                            expandedCategory = isExpanded ? nil : cat.key
                        }
                    }
                    .padding(.horizontal, 16)
                }
            }
        }
        .padding(.top, 8)
        .padding(.bottom, 20)
    }

    private func categoryDistributionBar(totalVisits: Int) -> some View {
        GeometryReader { geo in
            let spacing: CGFloat = 2
            let totalSpacing = spacing * CGFloat(max(categories.count - 1, 0))
            let availableWidth = geo.size.width - totalSpacing

            HStack(spacing: spacing) {
                ForEach(categories, id: \.key) { cat in
                    let share = totalVisits > 0 ? CGFloat(cat.totalVisits) / CGFloat(totalVisits) : 0
                    let width = max(share * availableWidth, 4)
                    let color = categoryColors[cat.key] ?? .gray

                    RoundedRectangle(cornerRadius: 4)
                        .fill(color)
                        .frame(width: width)
                }
            }
        }
        .frame(height: 14)
        .clipShape(Capsule())
    }

// MARK: - Diagonal Stripes

struct DiagonalStripes: View {
    let color: Color

    var body: some View {
        Canvas { context, size in
            let w: CGFloat = 4
            let step: CGFloat = 10
            for x in stride(from: -size.height, through: size.width + size.height, by: step) {
                var path = Path()
                path.move(to: CGPoint(x: x, y: size.height))
                path.addLine(to: CGPoint(x: x + size.height, y: 0))
                context.stroke(path, with: .color(color), lineWidth: w)
            }
        }
        .clipped()
        .opacity(0.3)
    }
}

}

// MARK: - Supporting Views

struct SummaryCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: icon)
                .font(.title2)
                .foregroundColor(color)
                .frame(width: 40, height: 40)
                .background(color.opacity(0.1))
                .cornerRadius(12)

            Text(value)
                .font(.system(.title2, design: .rounded).bold())

            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 16)
        .cardStyle()
    }
}

#Preview {
    StatsView()
}
