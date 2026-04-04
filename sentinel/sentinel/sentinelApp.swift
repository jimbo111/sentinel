import SwiftUI
import NetworkExtension

@main
struct sentinelApp: App {
    @StateObject private var vpnManager = VPNManager.shared
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false

    var body: some Scene {
        WindowGroup {
            Group {
                if !hasCompletedOnboarding {
                    OnboardingView()
                } else {
                    MainTabView()
                }
            }
            .environmentObject(vpnManager)
            .task { await onLaunch() }
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

        // Load cached threat feeds for instant protection, then refresh from network
        Task.detached(priority: .utility) {
            let _ = await ThreatFeedService.shared.loadCachedFeeds()
            let _ = await ThreatFeedService.shared.refreshFeeds()
        }

        // Request notification permission for threat alerts
        Task.detached(priority: .utility) {
            await ThreatAlertService.shared.requestPermission()
        }
    }
}
