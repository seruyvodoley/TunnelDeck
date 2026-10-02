import SwiftUI

@main
struct TunnelDeckApp: App {
    @StateObject private var model = AppViewModel()

    var body: some Scene {
        WindowGroup("TunnelDeck") { ContentView().environmentObject(model).frame(minWidth: 1060, minHeight: 700).sheet(isPresented: $model.showOnboarding) { OnboardingView().environmentObject(model) }.task { model.configurePolling(); await model.refresh() } }
            .commands { CommandGroup(after: .toolbar) { Button("Refresh") { Task { await model.refresh() } }.keyboardShortcut("r") } }
        MenuBarExtra { MenuBarView().environmentObject(model) } label: { Label("TunnelDeck", systemImage: model.system.health == .online ? "lock.shield.fill" : "lock.trianglebadge.exclamationmark") }
        Settings { SettingsView().environmentObject(model).frame(width: 520, height: 360) }
    }
}
