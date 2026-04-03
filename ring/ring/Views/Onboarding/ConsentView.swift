import SwiftUI

struct ConsentView: View {
    @AppStorage("hasCompletedConsent") private var hasCompletedConsent = false
    @State private var isSending = false

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            VStack(spacing: 16) {
                Image(systemName: "hand.raised.circle.fill")
                    .font(.system(size: 72))
                    .foregroundStyle(Theme.accent)

                Text("Data & Privacy")
                    .font(.system(size: 28, weight: .bold, design: .rounded))
                    .tracking(-0.5)

                Text("Ring collects anonymous usage data to improve site grouping accuracy. No browsing history or personal data is ever shared.")
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 8)
            }
            .padding(24)
            .cardStyle()
            .padding(.horizontal, 20)

            Spacer()

            Button(action: acceptAll) {
                if isSending {
                    ProgressView()
                        .tint(.white)
                        .frame(maxWidth: .infinity)
                        .padding()
                } else {
                    Text("Accept & Continue")
                        .font(.headline)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding()
                }
            }
            .background(Theme.accent)
            .cornerRadius(16)
            .padding(.horizontal, 32)
            .padding(.bottom, 16)
            .disabled(isSending)

            Button("Skip") {
                saveConsent(dns: false, analytics: false, crashes: false)
                hasCompletedConsent = true
            }
            .font(.subheadline)
            .foregroundColor(.secondary)
            .padding(.bottom, 48)
        }
        .background(Theme.lavender.opacity(0.15).ignoresSafeArea())
    }

    private func acceptAll() {
        isSending = true
        saveConsent(dns: true, analytics: true, crashes: true)

        Task {
            await ConsentService.shared.sendConsent(
                dnsTelemetry: true,
                usageAnalytics: true,
                crashReports: true
            )
            isSending = false
            hasCompletedConsent = true
        }
    }

    private func saveConsent(dns: Bool, analytics: Bool, crashes: Bool) {
        let defaults = AppGroupConfig.sharedDefaults
        defaults.set(dns, forKey: "consent_dns_telemetry")
        defaults.set(analytics, forKey: "consent_usage_analytics")
        defaults.set(crashes, forKey: "consent_crash_reports")
    }
}

#Preview {
    ConsentView()
}
