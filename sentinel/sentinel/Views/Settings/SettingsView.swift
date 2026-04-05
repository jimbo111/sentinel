import SwiftUI

struct SettingsView: View {
    @StateObject private var viewModel = SettingsViewModel()

    private let retentionOptions = [7, 14, 30, 60, 90]

    var body: some View {
        NavigationStack {
            Form {
                // General
                Section {
                    Toggle("Auto-Connect on Launch", isOn: $viewModel.settings.autoConnect)
                } header: {
                    sectionHeader(icon: "bolt.shield.fill", title: "General")
                } footer: {
                    Text("Starts protection automatically when you open Sentinel. The VPN stays active across sleep and network changes.")
                }

                // Protection Level
                Section {
                    protectionLevelPicker
                } header: {
                    sectionHeader(icon: "slider.horizontal.3", title: "Protection Level")
                } footer: {
                    Text("Controls how aggressively Sentinel blocks domains. Higher levels catch more threats but may flag legitimate sites.")
                }

                // Filtering
                Section {
                    Toggle("Filter Noise Domains", isOn: $viewModel.settings.filterNoise)
                        .onChange(of: viewModel.settings.filterNoise) { _, newValue in
                            viewModel.syncNoiseFilter(enabled: newValue)
                        }
                } header: {
                    sectionHeader(icon: "line.3.horizontal.decrease", title: "Domain Filtering")
                } footer: {
                    Text("Hides Apple infrastructure, CDNs, and analytics domains from your domain list. Keeps the view focused on sites you actually visit.")
                }

                // Data
                Section {
                    Picker("Retention Period", selection: $viewModel.settings.retentionDays) {
                        ForEach(retentionOptions, id: \.self) { days in
                            Text("\(days) days").tag(days)
                        }
                    }

                    Button {
                        viewModel.exportCSV()
                    } label: {
                        if viewModel.isExporting {
                            ProgressView()
                        } else {
                            Label("Export as CSV", systemImage: "square.and.arrow.up")
                        }
                    }
                    .disabled(viewModel.isExporting)

                    Button(role: .destructive) {
                        viewModel.showClearConfirmation = true
                    } label: {
                        Label("Clear All Data", systemImage: "trash")
                    }
                } header: {
                    sectionHeader(icon: "externaldrive.fill", title: "Your Data")
                } footer: {
                    Text("All data stays on your phone. Choose how long to keep domain history, export it, or delete everything.")
                }

                // Diagnostics
                Section {
                    NavigationLink {
                        DiagnosticsView()
                    } label: {
                        Label("Diagnostics & Logs", systemImage: "doc.text.magnifyingglass")
                    }
                } header: {
                    sectionHeader(icon: "wrench.and.screwdriver", title: "Debug")
                } footer: {
                    Text("View VPN tunnel status, database stats, and engine logs. Useful for troubleshooting.")
                }

                // About
                Section {
                    HStack {
                        Text("Version")
                        Spacer()
                        Text(viewModel.appVersion)
                            .foregroundColor(.secondary)
                    }

                    if let privacyURL = URL(string: "https://sentinel.jimmykim.com/privacy") {
                        Link(destination: privacyURL) {
                            HStack {
                                Text("Privacy Policy")
                                Spacer()
                                Image(systemName: "arrow.up.right.square")
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                } header: {
                    sectionHeader(icon: "info.circle", title: "About")
                }

                // How Sentinel works
                Section {
                    howItWorksCard
                } header: {
                    sectionHeader(icon: "questionmark.circle", title: "How It Works")
                }

                // Protection disclaimer
                Section {
                    Text("Sentinel blocks known threats from curated feeds updated daily. It cannot detect zero-day threats (2-7 day lag), iCloud Private Relay traffic, or URL-path attacks. ~0.1% of legitimate sites may be flagged — use the allowlist to bypass false positives.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .tint(Theme.accent)
            .navigationTitle("Settings")
            .confirmationDialog(
                "Clear All Data",
                isPresented: $viewModel.showClearConfirmation,
                titleVisibility: .visible
            ) {
                Button("Clear All Data", role: .destructive) {
                    viewModel.clearAllData()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This will permanently delete all recorded domains and visit history. This action cannot be undone.")
            }
            .sheet(isPresented: $viewModel.showExportSheet, onDismiss: {
                viewModel.cleanupExportFile()
            }) {
                if let url = viewModel.csvFileURL {
                    ShareSheet(items: [url])
                }
            }
            .alert("Export Failed", isPresented: Binding(
                get: { viewModel.exportError != nil },
                set: { if !$0 { viewModel.exportError = nil } }
            )) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(viewModel.exportError ?? "")
            }
        }
    }

    // MARK: - Section Header

    private func sectionHeader(icon: String, title: String) -> some View {
        HStack(spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(Theme.accent)
            Text(title)
                .font(.subheadline.weight(.semibold))
                .foregroundColor(.primary)
        }
        .textCase(nil)
    }

    // MARK: - How It Works

    private var howItWorksCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            howItWorksRow(
                step: "1",
                icon: "antenna.radiowaves.left.and.right",
                color: Theme.accent,
                title: "Intercepts DNS",
                description: "Every domain your phone contacts passes through Sentinel's local VPN tunnel."
            )
            howItWorksRow(
                step: "2",
                icon: "shield.checkered",
                color: Theme.threatOrange,
                title: "Checks Threat Feeds",
                description: "Domains are matched against 400K+ known phishing, malware, and tracking domains."
            )
            howItWorksRow(
                step: "3",
                icon: "xmark.octagon.fill",
                color: Theme.threatRed,
                title: "Blocks Threats",
                description: "Matched domains get a sinkhole response — the connection fails instantly, before any data loads."
            )
            howItWorksRow(
                step: "4",
                icon: "lock.iphone",
                color: Theme.connected,
                title: "Stays On-Device",
                description: "Everything runs locally. No browsing data is ever sent to a server."
            )
        }
    }

    private func howItWorksRow(step: String, icon: String, color: Color, title: String, description: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            ZStack {
                Circle()
                    .fill(color.opacity(0.12))
                    .frame(width: 36, height: 36)
                Image(systemName: icon)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(color)
            }

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                Text(description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Protection Level Picker

extension SettingsView {
    var protectionLevelPicker: some View {
        VStack(spacing: 12) {
            HStack(spacing: 0) {
                ForEach(0..<3, id: \.self) { level in
                    let isSelected = viewModel.settings.protectionLevel == level
                    Button {
                        withAnimation(.spring(response: 0.3)) {
                            viewModel.settings.protectionLevel = level
                            viewModel.syncProtectionLevel(level: level)
                        }
                    } label: {
                        VStack(spacing: 6) {
                            Image(systemName: levelIcon(level))
                                .font(.system(size: 20, weight: .medium))
                                .foregroundStyle(isSelected ? .white : levelColor(level))
                                .frame(width: 40, height: 40)
                                .background(isSelected ? levelColor(level) : levelColor(level).opacity(0.1))
                                .clipShape(Circle())

                            Text(levelName(level))
                                .font(.system(size: 12, weight: isSelected ? .bold : .medium))
                                .foregroundStyle(isSelected ? levelColor(level) : .secondary)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 8)
                    }
                    .buttonStyle(.plain)
                }
            }

            Text(levelDescription(viewModel.settings.protectionLevel))
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: .infinity)
                .padding(.horizontal, 8)
                .animation(.none, value: viewModel.settings.protectionLevel)
        }
    }

    private func levelIcon(_ level: Int) -> String {
        switch level {
        case 0: return "shield"
        case 1: return "shield.lefthalf.filled"
        case 2: return "shield.fill"
        default: return "shield.lefthalf.filled"
        }
    }

    private func levelName(_ level: Int) -> String {
        switch level {
        case 0: return "Relaxed"
        case 1: return "Balanced"
        case 2: return "Strict"
        default: return "Balanced"
        }
    }

    private func levelColor(_ level: Int) -> Color {
        switch level {
        case 0: return Theme.connected
        case 1: return Theme.accent
        case 2: return Theme.threatRed
        default: return Theme.accent
        }
    }

    private func levelDescription(_ level: Int) -> String {
        switch level {
        case 0: return "Blocks only confirmed malware, phishing, and C2 servers. Fewest false positives."
        case 1: return "Blocks all known threats from feed matches. Good balance of protection and accuracy."
        case 2: return "Blocks all threats including subdomain matches. Maximum protection, more false positives."
        default: return ""
        }
    }
}

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

#Preview {
    SettingsView()
}
