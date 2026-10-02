import SwiftUI

struct ContentView: View {
    @EnvironmentObject var model: AppViewModel
    var body: some View {
        NavigationSplitView {
            List(SidebarSection.allCases, selection: $model.selectedSection) { section in Label(section.rawValue, systemImage: section.icon).tag(section) }
                .navigationTitle("TunnelDeck")
                .safeAreaInset(edge: .bottom) { HStack { StatusDot(state: model.system.health); Text(model.settings.writeModeEnabled ? "WRITE MODE" : "READ-ONLY").font(.caption.bold()); Spacer() }.padding() }
        } detail: { selectedView.navigationTitle(model.selectedSection.rawValue).toolbar { ToolbarItem { Button { Task { await model.refresh() } } label: { Label("Refresh", systemImage: "arrow.clockwise") }.disabled(model.isRefreshing) } } }
    }

    @ViewBuilder private var selectedView: some View {
        switch model.selectedSection {
        case .dashboard: DashboardView()
        case .doctor: DoctorView()
        case .monitoring: MonitoringView()
        case .wireGuard: WireGuardView()
        case .profiles: ProfilesView()
        case .antiZapret: AntiZapretView()
        case .services: ServicesView()
        case .dns: DNSView()
        case .diagnostics: DiagnosticsView()
        case .security: SecurityView()
        case .backups: BackupsView()
        case .activity: ActivityView()
        case .recovery: RecoveryView()
        case .router: RouterView()
        case .homeAccess: HomeAccessView()
        case .logs: LogViewer()
        case .settings: SettingsView()
        }
    }
}