import SwiftUI

/// Hero card displaying the total number of threats blocked.
/// Uses an animated counter for visual impact when the count changes.
struct ThreatCountCard: View {
    let count: Int
    let period: String

    @State private var displayedCount: Int = 0

    var body: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "shield.checkered")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(Theme.threatRed)

                Text("Threats Blocked")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(.secondary)
            }

            Text("\(displayedCount)")
                .font(.system(size: 56, weight: .bold, design: .rounded))
                .foregroundStyle(.primary)
                .contentTransition(.numericText(countsDown: false))

            Text(period)
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 28)
        .background(
            RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous)
                .fill(Theme.cardBackground)
                .overlay(
                    RoundedRectangle(cornerRadius: Theme.cardRadius, style: .continuous)
                        .stroke(Theme.threatRed.opacity(0.15), lineWidth: 1)
                )
        )
        .shadow(color: Theme.cardShadow, radius: 8, y: 2)
        .onAppear { animateCount() }
        .onChange(of: count) { _, _ in animateCount() }
    }

    private func animateCount() {
        withAnimation(.easeOut(duration: 0.6)) {
            displayedCount = count
        }
    }
}

#Preview {
    VStack(spacing: 16) {
        ThreatCountCard(count: 1247, period: "All Time")
        ThreatCountCard(count: 0, period: "Today")
    }
    .padding()
    .background(Theme.pageBackground)
}
