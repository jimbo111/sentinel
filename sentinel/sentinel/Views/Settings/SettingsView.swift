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
                    Text("General")
                        .font(.subheadline.weight(.semibold))
                        .foregroundColor(.primary)
                        .textCase(nil)
                }

                // Protection Level
                Section {
                    protectionLevelPicker
                } header: {
                    Text("Protection Level")
                        .font(.subheadline.weight(.semibold))
                        .foregroundColor(.primary)
                        .textCase(nil)
                }

                // Filtering
                Section {
                    Toggle("Filter Noise Domains", isOn: $viewModel.settings.filterNoise)
                        .onChange(of: viewModel.settings.filterNoise) { _, newValue in
                            viewModel.syncNoiseFilter(enabled: newValue)
                        }
                } header: {
                    Text("Filtering")
                        .font(.subheadline.weight(.semibold))
                        .foregroundColor(.primary)
                        .textCase(nil)
                } footer: {
                    Text("Hides common infrastructure domains like CDNs and analytics trackers.")
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
                    Text("Data")
                        .font(.subheadline.weight(.semibold))
                        .foregroundColor(.primary)
                        .textCase(nil)
                }

                // Diagnostics
                Section {
                    NavigationLink {
                        DiagnosticsView()
                    } label: {
                        Label("Diagnostics & Logs", systemImage: "doc.text.magnifyingglass")
                    }
                } header: {
                    Text("Debug")
                        .font(.subheadline.weight(.semibold))
                        .foregroundColor(.primary)
                        .textCase(nil)
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
                    Text("About")
                        .font(.subheadline.weight(.semibold))
                        .foregroundColor(.primary)
                        .textCase(nil)
                }

                // Protection disclaimer
                Section {
                    Text("Sentinel blocks known phishing, malware, and tracking domains using threat feeds updated daily. It cannot detect zero-day threats (typical detection lag: 2-7 days), threats delivered through iCloud Private Relay, or URL-path-based attacks. Sentinel is one layer of protection and should not be your sole security measure.\n\nThreat detection uses a probabilistic filter with a ~0.1% false positive rate. Legitimate sites may occasionally be flagged — use the allowlist to bypass false positives.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } header: {
                    Text("About Protection")
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

            // Description for selected level
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
