import SwiftUI
import NetworkExtension

struct ConnectButton: View {
    let status: NEVPNStatus
    let action: () -> Void

    private var isTransitioning: Bool {
        status == .connecting || status == .disconnecting || status == .reasserting
    }

    private var isConnected: Bool {
        status == .connected
    }

    private var ringColor: Color {
        if isConnected { return Theme.connected }
        if isTransitioning { return Theme.transitioning }
        return Theme.accent.opacity(0.4)
    }

    private var fillColor: Color {
        if isConnected { return Theme.connected.opacity(0.12) }
        if isTransitioning { return Theme.transitioning.opacity(0.10) }
        return Theme.accent.opacity(0.06)
    }

    var body: some View {
        Button(action: action) {
            ZStack {
                Circle()
                    .fill(fillColor)
                    .frame(width: 160, height: 160)

                Circle()
                    .stroke(ringColor, lineWidth: 4)
                    .frame(width: 160, height: 160)

                if isTransitioning {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: Theme.transitioning))
                        .scaleEffect(1.5)
                } else {
                    Image(systemName: isConnected ? "shield.checkered" : "shield.slash")
                        .font(.system(size: 48, weight: .medium))
                        .foregroundColor(isConnected ? Theme.connected : Theme.accent.opacity(0.4))
                }
            }
            .shadow(
                color: isConnected ? .clear : Theme.cardShadow,
                radius: isConnected ? 0 : 16,
                y: isConnected ? 0 : 4
            )
        }
        .disabled(isTransitioning)
        .accessibilityLabel(
            isConnected ? "Disable Sentinel protection" :
            isTransitioning ? "Sentinel connection in progress" :
            "Enable Sentinel protection"
        )
        .animation(.easeInOut(duration: 0.3), value: status)
    }
}

#Preview {
    VStack(spacing: 32) {
        ConnectButton(status: .disconnected) {}
        ConnectButton(status: .connected) {}
    }
}
