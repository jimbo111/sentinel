import ActivityKit
import SwiftUI
import WidgetKit

// MARK: - Brand Colors
// Defined here because the widget extension cannot import the main app's Theme.swift.

private let ringAccentColor: Color = Color(red: 140/255, green: 100/255, blue: 200/255)
private let connectedColor: Color = Color(red: 120/255, green: 210/255, blue: 90/255)
private let disconnectedColor: Color = Color.gray

// MARK: - Live Activity Widget

struct RingWidgetsLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: RingActivityAttributes.self) { context in
            RingLockScreenBanner(state: context.state)
        } dynamicIsland: { context in
            DynamicIsland {
                // Leading: brand icon + connection label
                DynamicIslandExpandedRegion(.leading) {
                    RingExpandedLeading(state: context.state)
                }
                // Trailing: live session timer
                DynamicIslandExpandedRegion(.trailing) {
                    RingExpandedTrailing(state: context.state)
                }
                // Center: prominent domain count
                DynamicIslandExpandedRegion(.center) {
                    RingExpandedCenter(state: context.state)
                }
                // Bottom: last visited domain
                DynamicIslandExpandedRegion(.bottom) {
                    RingExpandedBottom(state: context.state)
                }
            } compactLeading: {
                // Small shield icon — more visible than a dot
                Image(systemName: "shield.fill")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(
                        context.state.isConnected ? connectedColor : disconnectedColor
                    )
            } compactTrailing: {
                // Domain count + abbreviated unit
                HStack(spacing: 1) {
                    Text("\(context.state.domainsToday)")
                        .font(.caption2.monospacedDigit().weight(.bold))
                        .foregroundColor(ringAccentColor)
                    Text("d")
                        .font(.system(size: 9, weight: .medium))
                        .foregroundColor(ringAccentColor.opacity(0.7))
                }
            } minimal: {
                // Just the shield, tinted by status
                Image(systemName: "shield.fill")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundColor(
                        context.state.isConnected ? connectedColor : disconnectedColor
                    )
            }
        }
    }
}

// MARK: - Dynamic Island — Expanded Leading

private struct RingExpandedLeading: View {
    let state: RingActivityAttributes.ContentState

    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: state.isConnected ? "shield.checkered" : "shield.slash")
                .font(.system(size: 18, weight: .semibold))
                .foregroundColor(state.isConnected ? connectedColor : disconnectedColor)
            VStack(alignment: .leading, spacing: 0) {
                Text("Ring")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundColor(.primary)
                Text(state.isConnected ? "Protected" : "Off")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundColor(state.isConnected ? connectedColor : disconnectedColor)
            }
        }
        .padding(.leading, 2)
    }
}

// MARK: - Dynamic Island — Expanded Trailing

private struct RingExpandedTrailing: View {
    let state: RingActivityAttributes.ContentState

    var body: some View {
        if state.isConnected {
            Text(state.sessionStartDate, style: .timer)
                .font(.system(size: 11, weight: .medium).monospacedDigit())
                .foregroundColor(.secondary)
                .multilineTextAlignment(.trailing)
                .minimumScaleFactor(0.7)
        } else {
            Text("--:--")
                .font(.system(size: 11, weight: .medium).monospacedDigit())
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Dynamic Island — Expanded Center

private struct RingExpandedCenter: View {
    let state: RingActivityAttributes.ContentState

    var body: some View {
        VStack(spacing: 0) {
            Text("\(state.domainsToday)")
                .font(.system(size: 22, weight: .bold, design: .rounded).monospacedDigit())
                .foregroundColor(ringAccentColor)
            Text("domains")
                .font(.system(size: 9, weight: .regular))
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Dynamic Island — Expanded Bottom

private struct RingExpandedBottom: View {
    let state: RingActivityAttributes.ContentState

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: "arrow.up.right")
                .font(.system(size: 9, weight: .semibold))
                .foregroundColor(ringAccentColor.opacity(0.7))
            if state.lastDomain.isEmpty {
                Text("No recent activity")
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
            } else {
                Text(state.lastDomain)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(.primary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 4)
        .padding(.bottom, 2)
    }
}

// MARK: - Lock Screen Banner

private struct RingLockScreenBanner: View {
    let state: RingActivityAttributes.ContentState

    var body: some View {
        VStack(spacing: 14) {
            // Top row: app name + status pill
            HStack {
                HStack(spacing: 6) {
                    Image(systemName: state.isConnected ? "shield.checkered" : "shield.slash")
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundColor(state.isConnected ? connectedColor : disconnectedColor)
                    Text("Ring")
                        .font(.system(size: 15, weight: .bold))
                }

                Spacer()

                // Status pill
                HStack(spacing: 4) {
                    Circle()
                        .fill(state.isConnected ? connectedColor : disconnectedColor)
                        .frame(width: 6, height: 6)
                    Text(state.isConnected ? "Active" : "Off")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(state.isConnected ? connectedColor : disconnectedColor)
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(
                    Capsule()
                        .fill(
                            (state.isConnected ? connectedColor : disconnectedColor).opacity(0.12)
                        )
                )
            }

            // Middle: hero metric
            HStack(alignment: .firstTextBaseline, spacing: 5) {
                Text("\(state.domainsToday)")
                    .font(.system(size: 40, weight: .bold, design: .rounded).monospacedDigit())
                    .foregroundColor(ringAccentColor)
                Text("domains")
                    .font(.system(size: 14, weight: .medium))
                    .foregroundColor(.secondary)
                Spacer()
            }

            // Bottom: last domain
            if !state.lastDomain.isEmpty {
                HStack(spacing: 4) {
                    Image(systemName: "globe")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary)
                    Text(state.lastDomain)
                        .font(.system(size: 12))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Spacer()
                }
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 16)
        .activityBackgroundTint(
            state.isConnected
                ? Color(red: 140/255, green: 100/255, blue: 200/255).opacity(0.08)
                : Color.gray.opacity(0.08)
        )
    }
}

// MARK: - Previews

#Preview("Lock Screen — Connected", as: .content, using: RingActivityAttributes()) {
    RingWidgetsLiveActivity()
} contentStates: {
    RingActivityAttributes.ContentState(
        isConnected: true,
        domainsToday: 84,
        totalVisits: 312,
        lastDomain: "youtube.com",
        sessionStartDate: Date().addingTimeInterval(-2743)
    )
    RingActivityAttributes.ContentState(
        isConnected: false,
        domainsToday: 31,
        totalVisits: 88,
        lastDomain: "github.com",
        sessionStartDate: Date()
    )
}

#Preview("Dynamic Island — Expanded", as: .dynamicIsland(.expanded), using: RingActivityAttributes()) {
    RingWidgetsLiveActivity()
} contentStates: {
    RingActivityAttributes.ContentState(
        isConnected: true,
        domainsToday: 84,
        totalVisits: 312,
        lastDomain: "api.stripe.com",
        sessionStartDate: Date().addingTimeInterval(-2743)
    )
}

#Preview("Dynamic Island — Compact", as: .dynamicIsland(.compact), using: RingActivityAttributes()) {
    RingWidgetsLiveActivity()
} contentStates: {
    RingActivityAttributes.ContentState(
        isConnected: true,
        domainsToday: 84,
        totalVisits: 312,
        lastDomain: "youtube.com",
        sessionStartDate: Date().addingTimeInterval(-2743)
    )
}

#Preview("Dynamic Island — Minimal", as: .dynamicIsland(.minimal), using: RingActivityAttributes()) {
    RingWidgetsLiveActivity()
} contentStates: {
    RingActivityAttributes.ContentState(
        isConnected: true,
        domainsToday: 84,
        totalVisits: 312,
        lastDomain: "youtube.com",
        sessionStartDate: Date().addingTimeInterval(-2743)
    )
}
