import SwiftUI

struct OnboardingView: View {
    @EnvironmentObject var vpnManager: VPNManager
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    @State private var currentStep = 0
    @State private var showPermissionError = false

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            // Step content
            Group {
                switch currentStep {
                case 0: step1
                case 1: step2
                case 2: step3
                default: EmptyView()
                }
            }
            .transition(.asymmetric(
                insertion: .move(edge: .trailing).combined(with: .opacity),
                removal: .move(edge: .leading).combined(with: .opacity)
            ))
            .id(currentStep)

            Spacer()

            // Step dots
            HStack(spacing: 8) {
                ForEach(0..<3, id: \.self) { index in
                    Capsule()
                        .fill(index == currentStep ? Theme.accent : Color.gray.opacity(0.25))
                        .frame(width: index == currentStep ? 24 : 8, height: 8)
                        .animation(.spring(response: 0.3), value: currentStep)
                }
            }
            .padding(.bottom, 32)

            // CTA button
            Button(action: advanceStep) {
                HStack(spacing: 8) {
                    Text(currentStep == 2 ? "Enable Sentinel" : "Continue")
                        .font(.headline)
                    if currentStep < 2 {
                        Image(systemName: "arrow.right")
                            .font(.subheadline.weight(.semibold))
                    }
                }
                .foregroundColor(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 16)
                .background(Theme.accent)
                .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            }
            .padding(.horizontal, 32)
            .padding(.bottom, 48)
        }
        .background(Theme.blue.opacity(0.06).ignoresSafeArea())
        .animation(.easeInOut(duration: 0.35), value: currentStep)
        .alert("VPN Permission Required", isPresented: $showPermissionError) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Sentinel needs VPN permission to block threats. Please tap \"Enable Sentinel\" and allow the VPN when prompted.")
        }
    }

    // MARK: - Step 1: What does this do?

    private var step1: some View {
        VStack(spacing: 24) {
            // Visual: shield with threat types orbiting
            ZStack {
                Circle()
                    .fill(Theme.accent.opacity(0.08))
                    .frame(width: 160, height: 160)

                Circle()
                    .stroke(Theme.accent.opacity(0.15), lineWidth: 2)
                    .frame(width: 160, height: 160)

                Image(systemName: "shield.checkered")
                    .font(.system(size: 56, weight: .medium))
                    .foregroundStyle(Theme.accent)

                // Threat indicators around the shield
                threatBubble(icon: "xmark.circle.fill", color: Theme.threatRed, offset: (-60, -55))
                threatBubble(icon: "exclamationmark.triangle.fill", color: Theme.threatOrange, offset: (65, -40))
                threatBubble(icon: "eye.slash.fill", color: Theme.yellow, offset: (55, 55))
            }
            .padding(.bottom, 8)

            Text("Protection Across\nEvery App")
                .font(.system(size: 28, weight: .bold, design: .rounded))
                .multilineTextAlignment(.center)
                .tracking(-0.5)

            Text("Blocks fake login pages, malware sites, and scam domains before they load. Works across every app on your phone.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)
        }
        .padding(.horizontal, 20)
    }

    // MARK: - Step 2: What does it protect me from?

    private var step2: some View {
        VStack(spacing: 24) {
            // Visual: list of concrete threats
            VStack(spacing: 0) {
                threatRow(icon: "message.fill", color: Theme.threatRed, text: "Phishing links in texts & emails")
                Divider().padding(.leading, 52)
                threatRow(icon: "rectangle.on.rectangle.angled", color: Theme.threatOrange, text: "Malicious ads & pop-ups")
                Divider().padding(.leading, 52)
                threatRow(icon: "eye.trianglebadge.exclamationmark", color: Theme.yellow, text: "Trackers following you across apps")
                Divider().padding(.leading, 52)
                threatRow(icon: "server.rack", color: Theme.accent, text: "Malware command & control servers")
            }
            .padding(.vertical, 8)
            .background(Theme.cardBackground)
            .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
            .shadow(color: Theme.cardShadow, radius: 8, y: 2)
            .padding(.horizontal, 20)

            Text("What Sentinel\nCatches")
                .font(.system(size: 28, weight: .bold, design: .rounded))
                .multilineTextAlignment(.center)
                .tracking(-0.5)

            Text("400,000+ known threat domains, updated daily from security intelligence feeds.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)
        }
        .padding(.horizontal, 0)
    }

    // MARK: - Step 3: Why VPN?

    private var step3: some View {
        VStack(spacing: 24) {
            // Visual: device with local shield
            ZStack {
                RoundedRectangle(cornerRadius: 24, style: .continuous)
                    .fill(Theme.cardBackground)
                    .frame(width: 140, height: 200)
                    .shadow(color: Theme.cardShadow, radius: 12, y: 4)

                VStack(spacing: 12) {
                    Image(systemName: "iphone")
                        .font(.system(size: 48, weight: .thin))
                        .foregroundStyle(.secondary)

                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 28))
                        .foregroundStyle(Theme.connected)
                }

                // "Local" badge
                Text("LOCAL")
                    .font(.system(size: 9, weight: .bold, design: .rounded))
                    .tracking(1)
                    .foregroundStyle(Theme.connected)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(Theme.connected.opacity(0.12))
                    .clipShape(Capsule())
                    .offset(y: 85)
            }
            .padding(.bottom, 8)

            Text("Stays On\nYour Phone")
                .font(.system(size: 28, weight: .bold, design: .rounded))
                .multilineTextAlignment(.center)
                .tracking(-0.5)

            Text("Sentinel checks connections locally using a VPN profile. Nothing is sent to a server — your data stays on your phone.")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 24)
        }
        .padding(.horizontal, 20)
    }

    // MARK: - Components

    private func threatBubble(icon: String, color: Color, offset: (CGFloat, CGFloat)) -> some View {
        Image(systemName: icon)
            .font(.system(size: 18))
            .foregroundStyle(color)
            .frame(width: 36, height: 36)
            .background(color.opacity(0.12))
            .clipShape(Circle())
            .offset(x: offset.0, y: offset.1)
    }

    private func threatRow(icon: String, color: Color, text: String) -> some View {
        HStack(spacing: 14) {
            Image(systemName: icon)
                .font(.system(size: 16, weight: .medium))
                .foregroundStyle(color)
                .frame(width: 32, height: 32)
                .background(color.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

            Text(text)
                .font(.subheadline)
                .foregroundStyle(.primary)

            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }

    // MARK: - Actions

    private func advanceStep() {
        if currentStep < 2 {
            currentStep += 1
        } else {
            Task {
                do {
                    try await vpnManager.saveConfiguration()
                    try await vpnManager.connect()
                    hasCompletedOnboarding = true
                } catch {
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
