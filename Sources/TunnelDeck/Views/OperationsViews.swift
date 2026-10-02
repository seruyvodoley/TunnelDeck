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
    private func canWrite(_ unit: UnitStatus) -> Bool { model.settings.writeModeEnabled && model.helperVersion == HelperService.localVersion && unit.activeState != "not-found" && !unit.name.hasSuffix(".timer") }
}

struct SecurityView: View {
    @EnvironmentObject var model: AppViewModel
    private var publicListeners: [Listener] { model.listeners.filter { $0.isPublic || (!model.settings.host.isEmpty && $0.address == model.settings.host) } }
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
                        if publicListeners.isEmpty { Label("No public listeners detected", systemImage: "checkmark.circle.fill").foregroundStyle(.green) }
                        ForEach(publicListeners) { listener in HStack { StatusDot(state: listener.port == 53 || listener.process.localizedCaseInsensitiveContains("AdGuardHome") ? .critical : .warning); Text("\(listener.protocolName) \(listener.address):\(listener.port)"); Spacer(); Text(listener.process).foregroundStyle(.secondary) } }
                    }
                }
                Text("This screen audits discovered public listeners. Deeper SSH-policy, permission and failed-login auditing is not implemented in this build.").foregroundStyle(.secondary)
            }.padding(20)
        }
    }
}

struct BackupsView: View {
    @EnvironmentObject var model: AppViewModel
    @StateObject private var state = BackupScreenState()
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Server Backups").font(.title2.bold())
                Spacer()
                if let helperVersion = model.helperVersion { Text("Helper \(helperVersion)").foregroundStyle(.secondary) }
                Button("Create Emergency Kit") { state.showEmergencyKit = true }
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
                    TableColumn("Actions") { backup in HStack { Button("Download") { Task { await model.downloadBackup(backup) } }; Button("Preview Restore") { state.selectedBackup = backup; Task { await model.previewRestore(backup, type: state.restoreType); state.showRestore = model.restorePreview != nil } }.disabled(model.helperVersion != HelperService.localVersion) } }
                }
                Picker("Restore type", selection: $state.restoreType) { Text("WireGuard").tag("wireguard"); Text("AdGuard").tag("adguard"); Text("AntiZapret").tag("antizapret") }.pickerStyle(.segmented).padding(8)
            }
        }
        .sheet(isPresented: $state.showEmergencyKit) { EmergencyKitSheet(state: state) { model.createEmergencyKit(includeClientCredentials: false); state.showEmergencyKit = false } }
        .sheet(isPresented: $state.showRestore) { if let preview = model.restorePreview { RestorePreviewSheet(preview: preview, canRestore: model.settings.writeModeEnabled) { Task { if await model.applyRestore() { state.showRestore = false } } } cancel: { state.showRestore = false } } }
    }
}

@MainActor private final class BackupScreenState: ObservableObject { @Published var showEmergencyKit = false; @Published var includeCredentials = false; @Published var showRestore = false; @Published var restoreType = "wireguard"; @Published var selectedBackup: BackupRecord? }

private struct EmergencyKitSheet: View {
    @ObservedObject var state: BackupScreenState
    let create: () -> Void
    var body: some View { VStack(alignment: .leading, spacing: 16) {
        Text("Emergency Kit Contents").font(.title2.bold())
        GroupBox("Public recovery data") { VStack(alignment: .leading) { Label("Endpoint and public server metadata", systemImage: "checkmark.circle"); Label("Health report and recovery notes", systemImage: "checkmark.circle"); Label("Latest backup manifest reference", systemImage: "checkmark.circle") }.padding(8) }
        Toggle("Include client VPN credentials", isOn: $state.includeCredentials).disabled(true)
        Text("Client VPN configurations contain private credentials. The Emergency Kit must be encrypted. TunnelDeck does not currently have a verified non-interactive encrypted container implementation, so secret profiles cannot be included.").foregroundStyle(.orange)
        Label("Server WireGuard private keys and SSH private keys are never included.", systemImage: "lock.shield.fill").foregroundStyle(.green)
        HStack { Spacer(); Button("Cancel") { state.showEmergencyKit = false }; Button("Create Public-Only Kit", action: create).buttonStyle(.borderedProminent) }
    }.padding(24).frame(width: 560) }
}

private struct RestorePreviewSheet: View {
    let preview: RestorePreview; let canRestore: Bool; let restore: () -> Void; let cancel: () -> Void
    var body: some View { VStack(alignment: .leading, spacing: 14) { Text("Preview Restore").font(.title2.bold()); KeyValueRow(key: "Backup", value: preview.backup); KeyValueRow(key: "Timestamp", value: preview.timestamp); KeyValueRow(key: "Operation", value: preview.operation); KeyValueRow(key: "Type", value: preview.type); Table(preview.files) { TableColumn("File", value: \.path); TableColumn("Current hash") { Text($0.currentSha256?.prefix(12) ?? "missing") }; TableColumn("Backup hash") { Text($0.backupSha256.prefix(12)) }; TableColumn("Diff", value: \.diffSummary) }.frame(height: 220); Label("Manifest paths and SHA-256 were verified. A current-state backup will be created before restore.", systemImage: "checkmark.shield.fill").foregroundStyle(.green); HStack { Spacer(); Button("Cancel", action: cancel); Button("Restore verified files", role: .destructive, action: restore).disabled(!canRestore) } }.padding(24).frame(width: 850) }
}