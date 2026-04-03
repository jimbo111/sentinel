import SwiftUI

struct OnboardingView: View {
    @EnvironmentObject var vpnManager: VPNManager
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    @State private var currentStep = 0
    @State private var showPermissionError = false

    private let steps: [(icon: String, title: String, description: String)] = [
        (
            "eye.circle.fill",
            "See Your Digital Footprint",
            "Ring silently observes every domain your device connects to — giving you full visibility into your network activity. Domain names are stored only on your device."
        ),
        (
            "lock.shield.fill",
            "100% On-Device",
            "All data is stored locally. No cloud servers, no tracking, no third-party analytics. Your browsing history stays yours."
        ),
        (
            "network.badge.shield.half.filled",
            "VPN Permission",
            "Ring uses a local VPN to inspect DNS headers. DNS queries are forwarded to a public resolver (Google DNS) for normal resolution — Ring only records which domains were queried."
        ),
    ]

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            // Step content card
            VStack(spacing: 0) {
                Image(systemName: steps[currentStep].icon)
                    .font(.system(size: 72))
                    .foregroundStyle(Theme.accent)
                    .padding(.bottom, 24)
                    .id(currentStep)
                    .transition(.opacity)

                Text(steps[currentStep].title)
                    .font(.system(size: 28, weight: .bold, design: .rounded))
                    .tracking(-0.5)
                    .multilineTextAlignment(.center)
                    .padding(.bottom, 12)
                    .id("title-\(currentStep)")
                    .transition(.opacity)

                Text(steps[currentStep].description)
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .id("desc-\(currentStep)")
                    .transition(.opacity)
            }
            .padding(24)
            .cardStyle()
            .padding(.horizontal, 20)

            Spacer()

            // Step dots
            HStack(spacing: 8) {
                ForEach(0..<steps.count, id: \.self) { index in
                    Circle()
                        .fill(index == currentStep ? Theme.accent : Color.gray.opacity(0.3))
                        .frame(width: 8, height: 8)
                }
            }
            .padding(.bottom, 32)

            // CTA button
            Button(action: advanceStep) {
                Text(currentStep == steps.count - 1 ? "Enable Ring" : "Next")
                    .font(.headline)
                    .foregroundColor(.white)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Theme.accent)
                    .cornerRadius(16)
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 48)
        }
        .background(Theme.lavender.opacity(0.15).ignoresSafeArea())
        .animation(.easeInOut(duration: 0.3), value: currentStep)
        .alert("VPN Permission Required", isPresented: $showPermissionError) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Ring needs VPN permission to observe network traffic on-device. Please tap \"Enable Ring\" and grant the VPN permission when prompted.")
        }
    }

    private func advanceStep() {
        if currentStep < steps.count - 1 {
            currentStep += 1
        } else {
            Task {
                do {
                    try await vpnManager.saveConfiguration()
                    try await vpnManager.connect()
                    hasCompletedOnboarding = true
                } catch {
                    // Do not mark onboarding complete — the VPN profile was
                    // not saved. Show an actionable alert instead (H8).
                    showPermissionError = true
                }
            }
        }
    }
}

#Preview {
    OnboardingView()
        .environmentObject(VPNManager.shared)
}
