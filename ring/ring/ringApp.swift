import SwiftUI
import NetworkExtension

@main
struct sentinelApp: App {
    @StateObject private var vpnManager = VPNManager.shared
    @Environment(\.scenePhase) private var scenePhase
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    @AppStorage("hasCompletedConsent") private var hasCompletedConsent = false

    var body: some Scene {
        WindowGroup {
            Group {
                if !hasCompletedOnboarding {
                    OnboardingView()
                } else if !hasCompletedConsent {
                    ConsentView()
                } else {
                    MainTabView()
                }
            }
            .environmentObject(vpnManager)
            .task { await onLaunch() }
            .onChange(of: scenePhase) { _, newPhase in
                if newPhase == .active {
                    Task { await syncTelemetryIfReady() }
                }
            }
        }
    }

    private func onLaunch() async {
        let settings = UserSettings()

        // Enforce data retention by deleting old visits.
        let retentionDays = settings.retentionDays
        if retentionDays > 0 {
            Task.detached(priority: .utility) {
                DatabaseReader.shared.cleanupOldVisits(olderThanDays: retentionDays)
            }
        }

        // Auto-connect if the user enabled it and onboarding is done.
        if hasCompletedOnboarding && settings.autoConnect {
            if vpnManager.status == .disconnected || vpnManager.status == .invalid {
                try? await vpnManager.connect()
            }
        }

        // Retry consent sync if it failed on first launch
        Task.detached(priority: .utility) {
            await ConsentService.shared.retrySyncIfNeeded()
        }

        // Fetch updated config from backend
        Task.detached(priority: .utility) {
            await ConfigService.shared.fetchUpdatedMappings()
        }

        // Start shopping deal notifications
        ShoppingNotificationService.shared.startListening()

        // Load cached threat feeds for instant protection, then refresh from network
        Task.detached(priority: .utility) {
            let _ = await ThreatFeedService.shared.loadCachedFeeds()
            let _ = await ThreatFeedService.shared.refreshFeeds()
        }

        // Request notification permission for threat alerts
        Task.detached(priority: .utility) {
            await ThreatAlertService.shared.requestPermission()
        }

        // Sync telemetry on launch
        await syncTelemetryIfReady()
    }

    /// Sync telemetry to backend if consent is granted and data exists.
    private func syncTelemetryIfReady() async {
        guard hasCompletedConsent else { return }
        await TelemetryService.shared.syncTelemetry()
    }
}
