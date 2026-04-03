import SwiftUI
import NetworkExtension

struct MainTabView: View {
    @EnvironmentObject var vpnManager: VPNManager

    var body: some View {
        TabView {
            ThreatDashboardView()
                .tabItem {
                    Label("Security", systemImage: "shield.checkered")
                }

            ConnectionView()
                .tabItem {
                    Label("Home", systemImage: "network")
                }

            DomainListView()
                .tabItem {
                    Label("Domains", systemImage: "list.bullet")
                }

            StatsView()
                .tabItem {
                    Label("Stats", systemImage: "chart.bar")
                }

            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gearshape")
                }
        }
        .tint(Theme.accent)
    }
}

#Preview {
    MainTabView()
        .environmentObject(VPNManager.shared)
}
