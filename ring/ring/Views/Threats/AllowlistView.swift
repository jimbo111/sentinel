import SwiftUI

/// Manages the threat allowlist: lists allowlisted domains with add/remove.
struct AllowlistView: View {
    @State private var domains: [String] = []
    @State private var showAddSheet = false
    @State private var newDomain = ""
    @State private var showValidationError = false
    @State private var validationErrorMessage = ""

    var body: some View {
        Group {
            if domains.isEmpty {
                emptyState
            } else {
                List {
                    ForEach(domains, id: \.self) { domain in
                        HStack(spacing: 12) {
                            Image(systemName: "checkmark.shield")
                                .font(.system(size: 14, weight: .medium))
                                .foregroundStyle(Theme.connected)
                                .frame(width: 28, height: 28)
                                .background(Theme.connected.opacity(0.1))
                                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

                            Text(domain)
                                .font(.system(size: 15, weight: .medium))
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                    .onDelete(perform: deleteDomains)
                }
                .listStyle(.insetGrouped)
            }
        }
        .background(Theme.pageBackground)
        .navigationTitle("Allowlist")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    newDomain = ""
                    showAddSheet = true
                } label: {
                    Image(systemName: "plus")
                }
            }
        }
        .alert("Add Domain", isPresented: $showAddSheet) {
            TextField("example.com", text: $newDomain)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("Cancel", role: .cancel) {}
            Button("Add") {
                addDomain()
            }
        } message: {
            Text("Enter a domain to allowlist. Connections to this domain will not be blocked.")
        }
        .onAppear { loadAllowlist() }
        .alert("Invalid Domain", isPresented: $showValidationError) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(validationErrorMessage)
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()

            Image(systemName: "checklist")
                .font(.system(size: 48))
                .foregroundStyle(.tertiary)

            Text("No Allowlisted Domains")
                .font(.headline)

            Text("Domains you allowlist from threat alerts will appear here.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 32)

            Spacer()
        }
        .frame(maxWidth: .infinity)
    }

    private func loadAllowlist() {
        domains = DatabaseReader.shared.fetchAllowlist()
    }

    private func addDomain() {
        let trimmed = newDomain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !trimmed.isEmpty else { return }

        if trimmed.contains(" ") {
            validationErrorMessage = "Domain must not contain spaces. Enter a hostname like \"example.com\"."
            showValidationError = true
            return
        }

        if !trimmed.contains(".") {
            validationErrorMessage = "Enter a valid domain name containing a dot, such as \"example.com\"."
            showValidationError = true
            return
        }

        // Reject labels that start or end with a hyphen, or the domain starts with a dot
        if trimmed.hasPrefix(".") || trimmed.hasSuffix(".") {
            validationErrorMessage = "Domain must not start or end with a dot."
            showValidationError = true
            return
        }

        DatabaseReader.shared.addToAllowlist(domain: trimmed)
        loadAllowlist()
    }

    private func deleteDomains(at offsets: IndexSet) {
        for index in offsets {
            let domain = domains[index]
            DatabaseReader.shared.removeFromAllowlist(domain: domain)
        }
        loadAllowlist()
    }
}

#Preview {
    NavigationStack {
        AllowlistView()
    }
}
