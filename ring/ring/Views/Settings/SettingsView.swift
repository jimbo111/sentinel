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
