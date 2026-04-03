import ActivityKit
import Foundation
import os.log

/// Manages the lifecycle of the Ring Live Activity shown on the lock screen
/// and Dynamic Island. Singleton — driven by `ConnectionViewModel`.
@MainActor
final class LiveActivityManager {
    static let shared = LiveActivityManager()

    private var activity: Activity<SentinelActivityAttributes>?
    private var sessionStartDate: Date?
    private let log = OSLog(subsystem: "com.jimmykim.sentinel", category: "LiveActivity")

    private init() {}

    // MARK: - Public API

    /// Start a new Live Activity when the VPN connects.
    func startActivity() {
        guard ActivityAuthorizationInfo().areActivitiesEnabled else {
            os_log(.info, log: log, "Live Activities not enabled by user")
            return
        }

        // End any stale activity before starting a new one.
        if activity != nil {
            stopActivity()
        }

        let now = Date()
        sessionStartDate = now

        let attributes = SentinelActivityAttributes()
        let initialState = SentinelActivityAttributes.ContentState(
            isConnected: true,
            domainsToday: 0,
            totalVisits: 0,
            lastDomain: "",
            sessionStartDate: now
        )

        do {
            activity = try Activity.request(
                attributes: attributes,
                content: .init(state: initialState, staleDate: nil),
                pushType: nil
            )
            os_log(.default, log: log, "Live Activity started (id: %{public}@)",
                   activity?.id ?? "nil")
        } catch {
            os_log(.error, log: log, "Failed to start Live Activity: %{public}@",
                   error.localizedDescription)
        }
    }

    /// Push updated stats to the Live Activity. Called every stats polling interval.
    func updateActivity(domainsToday: Int, totalVisits: Int, lastDomain: String) {
        guard let activity else { return }
        guard let startDate = sessionStartDate else { return }

        let state = SentinelActivityAttributes.ContentState(
            isConnected: true,
            domainsToday: domainsToday,
            totalVisits: totalVisits,
            lastDomain: lastDomain,
            sessionStartDate: startDate
        )

        Task {
            await activity.update(.init(state: state, staleDate: nil))
        }
    }

    /// End the Live Activity when the VPN disconnects.
    func stopActivity() {
        guard let activity else { return }

        let finalState = SentinelActivityAttributes.ContentState(
            isConnected: false,
            domainsToday: 0,
            totalVisits: 0,
            lastDomain: "",
            sessionStartDate: sessionStartDate ?? Date()
        )

        Task {
            await activity.end(.init(state: finalState, staleDate: nil),
                               dismissalPolicy: .immediate)
        }

        self.activity = nil
        self.sessionStartDate = nil
        os_log(.default, log: log, "Live Activity stopped")
    }
}
