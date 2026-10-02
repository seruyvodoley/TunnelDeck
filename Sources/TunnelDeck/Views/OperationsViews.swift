import SwiftUI

private final class ServicesScreenState: ObservableObject {
    @Published var action = ""
    @Published var unit = ""
    @Published var confirming = false
    func request(_ action: String, unit: String) { self.action = action; self.unit = unit; confirming = true }
}

struct ServicesView: View {
    @EnvironmentObject var model: AppViewModel
    @StateObject private var state = ServicesScreenState()
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Detected systemd units").font(.title2.bold())
                Spacer()
                Label(model.settings.writeModeEnabled ? "Write Mode" : "Read Only", systemImage: model.settings.writeModeEnabled ? "exclamationmark.shield" : "lock")
                    .foregroundStyle(model.settings.writeModeEnabled ? .orange : .green)
            }.padding()
            Table(model.units) {
                TableColumn("Service", value: \.name)
                TableColumn("State") { unit in HStack { StatusDot(state: unit.health); Text(unit.activeState) } }
                TableColumn("Substate", value: \.subState)
                TableColumn("Actions") { unit in
                    HStack {
                        Button("Start") { state.request("start", unit: unit.name) }.disabled(!canWrite(unit))
                        Button("Stop") { state.request("stop", unit: unit.name) }.disabled(!canWrite(unit))
                        Button("Restart") { state.request("restart", unit: unit.name) }.disabled(!canWrite(unit))
                    }
                }
            }
            Text(model.helperVersion == nil ? "Actions unavailable: server helper is not installed or SSH is unavailable." : "Every service action creates a server backup and requires confirmation.")
                .font(.caption).foregroundStyle(.secondary).padding(8)
        }
        .confirmationDialog("Confirm service operation", isPresented: $state.confirming, titleVisibility: .visible) {
            Button("\(state.action.capitalized) \(state.unit)", role: state.action == "stop" ? .destructive : nil) {
                Task { _ = await model.performServiceAction(state.action, unit: state.unit) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("TunnelDeck will create a scoped backup, \(state.action) \(state.unit), and verify its resulting state. Network services may briefly disconnect.")
        }
    }
    private func canWrite(_ unit: UnitStatus) -> Bool { model.settings.writeModeEnabled && model.helperVersion == HelperService.localVersion && unit.activeState != "not-found" }
}

struct SecurityView: View {
    @EnvironmentObject var model: AppViewModel
    private var publicListeners: [Listener] { model.listeners.filter(\.isPublic) }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                MetricCard(title: "Connection Security", icon: "key") {
                    VStack(spacing: 8) {
                        KeyValueRow(key: "SSH host", value: "\(model.settings.username)@\(model.settings.host):\(model.settings.port)")
                        KeyValueRow(key: "Identity", value: model.settings.keyPath)
                        KeyValueRow(key: "Host key policy", value: "Strict checking")
                        KeyValueRow(key: "Write mode", value: model.settings.writeModeEnabled ? "Enabled" : "Disabled")
                    }
                }
                MetricCard(title: "Public Listeners", icon: "network.badge.shield.half.filled") {
                    VStack(alignment: .leading, spacing: 8) {
                        if publicListeners.isEmpty { Label("No wildcard listeners detected", systemImage: "checkmark.circle.fill").foregroundStyle(.green) }
                        ForEach(publicListeners) { listener in HStack { StatusDot(state: listener.port == 53 ? .offline : .warning); Text("\(listener.protocolName) \(listener.address):\(listener.port)"); Spacer(); Text(listener.process).foregroundStyle(.secondary) } }
                    }
                }
                Text("Additional SSH configuration, firewall policy, permissions and failed-login checks require successful SSH discovery.").foregroundStyle(.secondary)
            }.padding(20)
        }
    }
}

struct BackupsView: View {
    @EnvironmentObject var model: AppViewModel
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Server Backups").font(.title2.bold())
                Spacer()
                if let helperVersion = model.helperVersion { Text("Helper \(helperVersion)").foregroundStyle(.secondary) }
                Button("Create Emergency Kit") { model.createEmergencyKit() }
                Button("Backup Now") { Task { _ = await model.createBackup(operation: "manual") } }.disabled(!model.settings.writeModeEnabled || model.helperVersion != HelperService.localVersion)
                Button("Refresh") { Task { await model.refreshHelper() } }
            }.padding()
            if model.helperVersion == nil {
                ContentUnavailableView("Server helper not installed", systemImage: "shippingbox", description: Text(model.helperError?.message ?? "SSH access is required before helper installation."))
            } else {
                Table(model.backups) {
                    TableColumn("Date", value: \.timestamp)
                    TableColumn("Operation", value: \.operation)
                    TableColumn("Host", value: \.hostname)
                    TableColumn("Files") { Text(String($0.files.count)) }
                    TableColumn("Size") { Text(ByteCountFormatter.string(fromByteCount: $0.size, countStyle: .file)) }
                    TableColumn("Actions") { backup in HStack { Button("Download") { Task { await model.downloadBackup(backup) } }; Button("Restore") {}.disabled(true) } }
                }
                Text("Restore remains unavailable until helper restore preview and rollback validation are present on the server.").font(.caption).foregroundStyle(.secondary).padding(8)
            }
        }
    }
}
