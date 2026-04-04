import SwiftUI

/// Detail view for a single threat record.
struct ThreatDetailView: View {
    let threat: ThreatRecord

    @Environment(\.dismiss) private var dismiss
    @State private var isAllowlisted = false
    @State private var showAllowlistConfirm = false

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                // Threat icon hero
                VStack(spacing: 12) {
                    ZStack {
                        Circle()
                            .fill(threat.threatColor.opacity(0.12))
                            .frame(width: 80, height: 80)

                        Image(systemName: threat.threatIcon)
                            .font(.system(size: 36, weight: .semibold))
                            .foregroundStyle(threat.threatColor)
                    }

                    Text(threat.threatTypeDisplay)
                        .font(.system(size: 20, weight: .bold))
                        .foregroundStyle(threat.threatColor)

                    Text(threat.domain)
                        .font(.system(size: 15, weight: .medium, design: .monospaced))
                        .foregroundStyle(.primary)
                        .lineLimit(2)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 24)
                .cardStyle()

                // Details card
                VStack(spacing: 0) {
                    detailRow(label: "Domain", value: threat.domain)
                    Divider().padding(.horizontal, 14)
                    detailRow(label: "Threat Type", value: threat.threatTypeDisplay)
                    Divider().padding(.horizontal, 14)
                    detailRow(label: "Feed Source", value: threat.feedName)
                    Divider().padding(.horizontal, 14)
                    detailRow(label: "Confidence", value: threat.confidencePercent)
                    Divider().padding(.horizontal, 14)
                    detailRow(label: "Detected", value: threat.dateFormatted)
                }
                .cardStyle()

                // Actions
                VStack(spacing: 12) {
                    if isAllowlisted {
                        HStack(spacing: 8) {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundStyle(Theme.connected)
                            Text("Domain is allowlisted")
                                .font(.subheadline.weight(.medium))
                                .foregroundStyle(Theme.connected)
                        }
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 14)
                        .background(Theme.connected.opacity(0.1))
                        .cornerRadius(12)
                    } else {
                        Button {
                            showAllowlistConfirm = true
                        } label: {
                            HStack(spacing: 8) {
                                Image(systemName: "plus.circle.fill")
                                Text("Add to Allowlist")
                                    .font(.system(size: 16, weight: .semibold))
                            }
                            .foregroundStyle(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 14)
                            .background(Theme.accent.gradient, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                        }
                    }
                }
                .padding(.top, 4)
            }
            .padding(16)
        }
        .background(Theme.pageBackground)
        .navigationTitle("Threat Details")
        .navigationBarTitleDisplayMode(.inline)
        .onAppear {
            isAllowlisted = DatabaseReader.shared.isAllowlisted(domain: threat.domain)
        }
        .alert("Add to Allowlist?", isPresented: $showAllowlistConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Allowlist") {
                DatabaseReader.shared.addToAllowlist(domain: threat.domain)
                isAllowlisted = true
                // Brief pause so the user sees the success banner, then pop back.
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
                    dismiss()
                }
            }
        } message: {
            Text("Future connections to \(threat.domain) will no longer be blocked. Only allowlist domains you trust.")
        }
    }

    private func detailRow(label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.subheadline.weight(.medium))
                .foregroundStyle(.primary)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
    }
}

#Preview {
    NavigationStack {
        ThreatDetailView(threat: ThreatRecord(
            id: 1, domain: "phishing-bank-login.com", threatType: "phishing",
            feedName: "hagezi-pro", confidence: 0.95,
            timestampMs: Int64(Date().timeIntervalSince1970 * 1000), dismissed: false
        ))
    }
}
