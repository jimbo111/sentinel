# Design Elements (Swift UI)

## Design Philosophy

Clean, privacy-focused, utilitarian interface. The app should feel like a trusted security tool — not flashy, not gamified. Think Apple's built-in Settings app meets a modern VPN client.

---

## Color System

```swift
enum AppColors {
    // Primary brand color — used for the connect button and active states
    static let primary = Color("AccentGreen")        // #34C759 (SF Green)
    static let primaryDark = Color("AccentGreenDark") // #30B350

    // Status colors
    static let connected = Color.green               // Tunnel active
    static let disconnected = Color(.systemGray3)    // Tunnel off
    static let connecting = Color.orange             // In-progress

    // Surface colors (adaptive light/dark mode)
    static let background = Color(.systemBackground)
    static let secondaryBackground = Color(.secondarySystemBackground)
    static let groupedBackground = Color(.systemGroupedBackground)

    // Text
    static let primaryText = Color(.label)
    static let secondaryText = Color(.secondaryLabel)
    static let tertiaryText = Color(.tertiaryLabel)
}
```

---

## Typography

Use the system Dynamic Type scale throughout. No custom fonts.

| Element | Style | Weight |
|---------|-------|--------|
| Screen titles | `.largeTitle` | Bold |
| Section headers | `.headline` | Semibold |
| Domain names | `.body` | Regular |
| Visit counts | `.callout` | Medium |
| Timestamps | `.caption` | Regular |
| Stats numbers | `.title` | Bold |
| Stats labels | `.caption2` | Regular |

---

## Tab Structure

```
┌─────────────────────────────────────────────┐
│                 Main Tab Bar                  │
├──────────┬──────────┬──────────┬────────────┤
│  Shield  │  List    │  Chart   │  Gear      │
│  Home    │  Domains │  Stats   │  Settings  │
└──────────┴──────────┴──────────┴────────────┘
```

```swift
struct MainTabView: View {
    @StateObject private var vpnManager = VPNManager()

    var body: some View {
        TabView {
            ConnectionView()
                .tabItem {
                    Label("Home", systemImage: "shield.checkered")
                }

            DomainListView()
                .tabItem {
                    Label("Domains", systemImage: "list.bullet")
                }

            StatsView()
                .tabItem {
                    Label("Stats", systemImage: "chart.bar")
                }

            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gearshape")
                }
        }
        .environmentObject(vpnManager)
    }
}
```

---

## Screen 1: Home / Connection

The primary screen with the connect/disconnect button and at-a-glance status.

```
┌──────────────────────────────────┐
│          DomainGuard             │  ← Navigation title
│                                  │
│                                  │
│         ╭──────────────╮         │
│         │              │         │
│         │   ◉ Shield   │         │  ← Large circular button
│         │   Icon       │         │     Green when connected
│         │              │         │     Gray when disconnected
│         ╰──────────────╯         │
│                                  │
│        ● Connected               │  ← Status text + dot indicator
│        12 min active             │  ← Duration
│                                  │
│  ┌────────────────────────────┐  │
│  │ Domains Today    │   47    │  │  ← Quick stats cards
│  ├────────────────────────────┤  │
│  │ Packets Scanned  │  12.4K  │  │
│  ├────────────────────────────┤  │
│  │ DNS Queries      │   892   │  │
│  └────────────────────────────┘  │
│                                  │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  Home   Domains   Stats   Settings│
└──────────────────────────────────┘
```

### ConnectionView Implementation

```swift
struct ConnectionView: View {
    @EnvironmentObject var vpnManager: VPNManager
    @State private var sessionDuration: TimeInterval = 0
    @State private var stats: RustPacketEngine.Stats?

    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        NavigationStack {
            VStack(spacing: 32) {
                Spacer()

                // Connect Button
                ConnectButton(
                    status: vpnManager.status,
                    action: {
                        Task {
                            try? await vpnManager.toggle()
                        }
                    }
                )

                // Status Text
                VStack(spacing: 4) {
                    HStack(spacing: 6) {
                        Circle()
                            .fill(statusColor)
                            .frame(width: 8, height: 8)
                        Text(statusText)
                            .font(.headline)
                    }

                    if vpnManager.status == .connected {
                        Text(durationText)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                Spacer()

                // Quick Stats
                if vpnManager.status == .connected, let stats = stats {
                    QuickStatsGrid(stats: stats)
                        .padding(.horizontal)
                }

                Spacer()
            }
            .navigationTitle("DomainGuard")
            .onReceive(timer) { _ in
                Task {
                    self.stats = await vpnManager.requestStats()
                }
            }
        }
    }

    private var statusColor: Color {
        switch vpnManager.status {
        case .connected: return .green
        case .connecting, .reasserting: return .orange
        case .disconnecting: return .orange
        default: return Color(.systemGray3)
        }
    }

    private var statusText: String {
        switch vpnManager.status {
        case .connected: return "Connected"
        case .connecting: return "Connecting..."
        case .disconnecting: return "Disconnecting..."
        case .disconnected: return "Disconnected"
        case .invalid: return "Not Configured"
        case .reasserting: return "Reconnecting..."
        @unknown default: return "Unknown"
        }
    }

    private var durationText: String {
        let minutes = Int(sessionDuration) / 60
        let hours = minutes / 60
        if hours > 0 {
            return "\(hours)h \(minutes % 60)m active"
        } else {
            return "\(minutes) min active"
        }
    }
}
```

### Connect Button Component

```swift
struct ConnectButton: View {
    let status: NEVPNStatus
    let action: () -> Void

    private var isConnected: Bool { status == .connected }
    private var isTransitioning: Bool {
        status == .connecting || status == .disconnecting || status == .reasserting
    }

    var body: some View {
        Button(action: action) {
            ZStack {
                // Outer ring
                Circle()
                    .stroke(ringColor, lineWidth: 4)
                    .frame(width: 160, height: 160)

                // Fill
                Circle()
                    .fill(fillColor)
                    .frame(width: 148, height: 148)

                // Icon
                if isTransitioning {
                    ProgressView()
                        .scaleEffect(1.5)
                        .tint(.white)
                } else {
                    Image(systemName: isConnected
                          ? "shield.checkered"
                          : "shield.slash")
                        .font(.system(size: 48, weight: .medium))
                        .foregroundStyle(.white)
                }
            }
        }
        .disabled(isTransitioning)
        .animation(.easeInOut(duration: 0.3), value: status)
    }

    private var ringColor: Color {
        isConnected ? .green.opacity(0.3) : Color(.systemGray4)
    }

    private var fillColor: Color {
        if isTransitioning { return .orange }
        return isConnected ? .green : Color(.systemGray3)
    }
}
```

---

## Screen 2: Domain List

The core feature — a scrollable, searchable list of visited domains.

```
┌──────────────────────────────────┐
│  Domains              Filter ▼   │
│  ┌────────────────────────────┐  │
│  │ 🔍 Search domains...       │  │
│  └────────────────────────────┘  │
│                                  │
│  Today                           │
│  ┌────────────────────────────┐  │
│  │ 🌐 amazon.com         42x │  │
│  │    Last: 2 min ago    SNI  │  │
│  ├────────────────────────────┤  │
│  │ 🌐 google.com        128x │  │
│  │    Last: 5 min ago    DNS  │  │
│  ├────────────────────────────┤  │
│  │ 🌐 naver.com          15x │  │
│  │    Last: 12 min ago   DNS  │  │
│  ├────────────────────────────┤  │
│  │ 🌐 github.com         23x │  │
│  │    Last: 18 min ago   SNI  │  │
│  └────────────────────────────┘  │
│                                  │
│  Yesterday                       │
│  ┌────────────────────────────┐  │
│  │ 🌐 yahoo.co.jp        8x  │  │
│  │    Last: 1 day ago    DNS  │  │
│  └────────────────────────────┘  │
│                                  │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  Home   Domains   Stats   Settings│
└──────────────────────────────────┘
```

### DomainListView Implementation

```swift
struct DomainListView: View {
    @StateObject private var viewModel = DomainListViewModel()
    @State private var searchText = ""

    var body: some View {
        NavigationStack {
            List {
                ForEach(viewModel.groupedDomains, id: \.key) { group in
                    Section(header: Text(group.key)) {
                        ForEach(group.domains) { domain in
                            NavigationLink(destination: DomainDetailView(domain: domain)) {
                                DomainRowView(domain: domain)
                            }
                        }
                    }
                }
            }
            .listStyle(.insetGrouped)
            .searchable(text: $searchText, prompt: "Search domains...")
            .onChange(of: searchText) { newValue in
                viewModel.search(query: newValue)
            }
            .navigationTitle("Domains")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Menu {
                        Button("Most Recent") { viewModel.sortBy(.recent) }
                        Button("Most Visited") { viewModel.sortBy(.visitCount) }
                        Button("Alphabetical") { viewModel.sortBy(.alphabetical) }
                    } label: {
                        Label("Sort", systemImage: "line.3.horizontal.decrease")
                    }
                }
            }
            .refreshable {
                await viewModel.refresh()
            }
        }
    }
}
```

### Domain Row Component

```swift
struct DomainRowView: View {
    let domain: DomainRecord

    var body: some View {
        HStack(spacing: 12) {
            // Favicon placeholder (could use async image loading)
            Image(systemName: "globe")
                .font(.title3)
                .foregroundStyle(.secondary)
                .frame(width: 32, height: 32)

            VStack(alignment: .leading, spacing: 2) {
                Text(domain.domain)
                    .font(.body)
                    .lineLimit(1)

                HStack(spacing: 8) {
                    Text(domain.relativeTimeString)
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    Text(domain.source.uppercased())
                        .font(.caption2)
                        .fontWeight(.medium)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(
                            domain.source == "sni"
                                ? Color.blue.opacity(0.1)
                                : Color.green.opacity(0.1)
                        )
                        .foregroundStyle(
                            domain.source == "sni" ? .blue : .green
                        )
                        .clipShape(Capsule())
                }
            }

            Spacer()

            Text("\(domain.visitCount)x")
                .font(.callout)
                .fontWeight(.medium)
                .foregroundStyle(.secondary)
        }
        .padding(.vertical, 4)
    }
}
```

---

## Screen 3: Stats

Aggregated traffic statistics with simple charts.

```
┌──────────────────────────────────┐
│  Statistics                      │
│                                  │
│  ┌──────────┐  ┌──────────┐     │
│  │   523    │  │  12.4K   │     │
│  │ Domains  │  │  Visits  │     │
│  └──────────┘  └──────────┘     │
│                                  │
│  Domains Over Time               │
│  ┌────────────────────────────┐  │
│  │  📊 Bar chart              │  │
│  │  (domains per day,         │  │
│  │   last 7 days)             │  │
│  └────────────────────────────┘  │
│                                  │
│  Top Domains                     │
│  ┌────────────────────────────┐  │
│  │ 1. google.com       428x  │  │
│  │ 2. amazon.com       312x  │  │
│  │ 3. github.com       198x  │  │
│  │ 4. naver.com        156x  │  │
│  │ 5. youtube.com      134x  │  │
│  └────────────────────────────┘  │
│                                  │
│  Detection Breakdown             │
│  ┌────────────────────────────┐  │
│  │  🟢 DNS  62%  🔵 SNI  38% │  │
│  └────────────────────────────┘  │
│                                  │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  Home   Domains   Stats   Settings│
└──────────────────────────────────┘
```

### StatsView Implementation

```swift
import Charts

struct StatsView: View {
    @StateObject private var viewModel = StatsViewModel()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 24) {
                    // Summary cards
                    HStack(spacing: 16) {
                        StatCard(value: "\(viewModel.totalDomains)",
                                label: "Domains")
                        StatCard(value: viewModel.formattedVisits,
                                label: "Visits")
                        StatCard(value: "\(viewModel.domainsToday)",
                                label: "Today")
                    }
                    .padding(.horizontal)

                    // Domains per day chart (iOS 16+ Charts framework)
                    if #available(iOS 16, *) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Domains Over Time")
                                .font(.headline)
                                .padding(.horizontal)

                            Chart(viewModel.dailyDomainCounts) { item in
                                BarMark(
                                    x: .value("Day", item.date, unit: .day),
                                    y: .value("Domains", item.count)
                                )
                                .foregroundStyle(.green.gradient)
                            }
                            .frame(height: 200)
                            .padding(.horizontal)
                        }
                    }

                    // Top domains
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Top Domains")
                            .font(.headline)
                            .padding(.horizontal)

                        ForEach(Array(viewModel.topDomains.enumerated()), id: \.element.id) { index, domain in
                            HStack {
                                Text("\(index + 1).")
                                    .font(.callout)
                                    .foregroundStyle(.secondary)
                                    .frame(width: 28, alignment: .trailing)
                                Text(domain.domain)
                                    .font(.body)
                                Spacer()
                                Text("\(domain.visitCount)x")
                                    .font(.callout)
                                    .foregroundStyle(.secondary)
                            }
                            .padding(.horizontal)
                        }
                    }
                }
                .padding(.vertical)
            }
            .navigationTitle("Statistics")
        }
    }
}

struct StatCard: View {
    let value: String
    let label: String

    var body: some View {
        VStack(spacing: 4) {
            Text(value)
                .font(.title)
                .fontWeight(.bold)
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 16)
        .background(Color(.secondarySystemBackground))
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}
```

---

## Screen 4: Settings

```
┌──────────────────────────────────┐
│  Settings                        │
│                                  │
│  GENERAL                         │
│  ┌────────────────────────────┐  │
│  │ Auto-connect on launch  🔘 │  │
│  │ Show notifications      🔘 │  │
│  └────────────────────────────┘  │
│                                  │
│  FILTERING                       │
│  ┌────────────────────────────┐  │
│  │ Filter noise domains    🔘 │  │
│  │ Custom blacklist         > │  │
│  │ Custom whitelist         > │  │
│  └────────────────────────────┘  │
│                                  │
│  DATA                            │
│  ┌────────────────────────────┐  │
│  │ Data retention      30 days│  │
│  │ Export data              > │  │
│  │ Clear all data           > │  │
│  └────────────────────────────┘  │
│                                  │
│  ABOUT                           │
│  ┌────────────────────────────┐  │
│  │ Version             1.0.0  │  │
│  │ Privacy Policy           > │  │
│  └────────────────────────────┘  │
│                                  │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  Home   Domains   Stats   Settings│
└──────────────────────────────────┘
```

### SettingsView Implementation

```swift
struct SettingsView: View {
    @StateObject private var viewModel = SettingsViewModel()

    var body: some View {
        NavigationStack {
            Form {
                Section("General") {
                    Toggle("Auto-connect on launch", isOn: $viewModel.autoConnect)
                    Toggle("New domain notifications", isOn: $viewModel.showNotifications)
                }

                Section("Filtering") {
                    Toggle("Filter system noise", isOn: $viewModel.filterNoise)
                    NavigationLink("Custom blacklist") {
                        DomainFilterListView(mode: .blacklist)
                    }
                    NavigationLink("Custom whitelist") {
                        DomainFilterListView(mode: .whitelist)
                    }
                }

                Section("Data") {
                    Picker("Data retention", selection: $viewModel.retentionDays) {
                        Text("7 days").tag(7)
                        Text("14 days").tag(14)
                        Text("30 days").tag(30)
                        Text("90 days").tag(90)
                    }

                    Button("Export data as CSV") {
                        viewModel.exportCSV()
                    }

                    Button("Clear all data", role: .destructive) {
                        viewModel.showClearConfirmation = true
                    }
                    .confirmationDialog(
                        "Delete all browsing data?",
                        isPresented: $viewModel.showClearConfirmation
                    ) {
                        Button("Delete All", role: .destructive) {
                            viewModel.clearAllData()
                        }
                    }
                }

                Section("About") {
                    LabeledContent("Version", value: viewModel.appVersion)
                    NavigationLink("Privacy Policy") {
                        PrivacyPolicyView()
                    }
                }
            }
            .navigationTitle("Settings")
        }
    }
}
```

---

## Domain Detail View

Shown when tapping a domain in the list.

```swift
struct DomainDetailView: View {
    let domain: DomainRecord
    @StateObject private var viewModel: DomainDetailViewModel

    init(domain: DomainRecord) {
        self.domain = domain
        _viewModel = StateObject(wrappedValue: DomainDetailViewModel(domainId: domain.id))
    }

    var body: some View {
        List {
            Section {
                LabeledContent("Domain", value: domain.domain)
                LabeledContent("Total visits", value: "\(domain.visitCount)")
                LabeledContent("First seen", value: domain.firstSeenFormatted)
                LabeledContent("Last seen", value: domain.lastSeenFormatted)
                LabeledContent("Detection", value: domain.source.uppercased())
            }

            Section("Recent Visits") {
                ForEach(viewModel.visits) { visit in
                    HStack {
                        Text(visit.formattedTime)
                            .font(.body)
                        Spacer()
                        Text(visit.source.uppercased())
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .navigationTitle(domain.domain)
        .navigationBarTitleDisplayMode(.inline)
    }
}
```

---

## Accessibility

All views must support:

| Feature | Implementation |
|---------|---------------|
| Dynamic Type | Use system text styles exclusively (`.body`, `.caption`, etc.) |
| VoiceOver | All interactive elements have meaningful `accessibilityLabel` |
| Reduce Motion | Respect `UIAccessibility.isReduceMotionEnabled` for connect button animation |
| High Contrast | Use system semantic colors (`.label`, `.systemBackground`) |
| Bold Text | System fonts handle this automatically |

---

## Launch Screen

Simple centered app icon on system background color. No splash animation — the app should launch fast.

```swift
// LaunchScreen.storyboard equivalent in SwiftUI
struct LaunchScreenView: View {
    var body: some View {
        ZStack {
            Color(.systemBackground)
                .ignoresSafeArea()
            Image("AppIcon")
                .resizable()
                .frame(width: 80, height: 80)
                .clipShape(RoundedRectangle(cornerRadius: 18))
        }
    }
}
```

---

## First-Launch Onboarding

On first launch, show a 3-step onboarding flow explaining what the app does and requesting VPN permission.

| Step | Title | Description | Action |
|------|-------|-------------|--------|
| 1 | "See Your Digital Footprint" | "DomainGuard shows you every website and service your phone connects to." | Next |
| 2 | "100% On-Device" | "All traffic analysis happens locally on your phone. Nothing is sent to our servers." | Next |
| 3 | "VPN Permission" | "iOS requires VPN permission to inspect network traffic. This creates a local tunnel — your data never leaves your device." | "Enable DomainGuard" (triggers VPN permission dialog) |
