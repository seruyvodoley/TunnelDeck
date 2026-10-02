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

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Security").font(.title2.bold())
                        HStack(spacing: 8) {
                            StatusDot(state: model.security.state)
                            Text(securityLabel).foregroundStyle(.secondary)
                            if let updated = model.security.lastUpdated {
                                Text("· \(updated.formatted(date: .omitted, time: .standard))").foregroundStyle(.tertiary)
                            }
                        }
                    }
                    Spacer()
                    Button(model.isRefreshingSecurity ? "Auditing…" : "Run Security Audit") {
                        Task { await model.refreshSecurityAudit() }
                    }
                    .disabled(model.isRefreshingSecurity)
                }

                MetricCard(title: "Connection Security", icon: "key") {
                    VStack(spacing: 8) {
                        KeyValueRow(key: "SSH host", value: "\(model.settings.username)@\(model.settings.host):\(model.settings.port)")
                        KeyValueRow(key: "Identity", value: model.settings.keyPath)
                        KeyValueRow(key: "Host key policy", value: "Strict checking")
                        KeyValueRow(key: "Write mode", value: model.settings.writeModeEnabled ? "Enabled" : "Disabled")
                    }
                }

                MetricCard(title: "Public Services", icon: "network.badge.shield.half.filled") {
                    VStack(alignment: .leading, spacing: 10) {
                        if model.security.publicListeners.isEmpty {
                            Text(model.security.lastUpdated == nil ? "Run Security Audit to classify public services." : "No public listeners detected.")
                                .foregroundStyle(.secondary)
                        }
                        ForEach(model.security.publicListeners) { listener in
                            listenerRow(listener)
                        }
                    }
                }

                MetricCard(title: "VPN / Private Services", icon: "lock.shield") {
                    VStack(alignment: .leading, spacing: 10) {
                        if model.security.privateListeners.isEmpty {
                            Text("No private AdGuard/WireGuard listeners classified.").foregroundStyle(.secondary)
                        }
                        ForEach(model.security.privateListeners) { listener in
                            listenerRow(listener)
                        }
                    }
                }

                MetricCard(title: "SSH Hardening", icon: "terminal") {
                    if !model.security.ssh.available {
                        Text(model.security.lastUpdated == nil ? "Run Security Audit to inspect the effective sshd policy." : "Effective sshd configuration was not available.")
                            .foregroundStyle(.secondary)
                    } else {
                        VStack(alignment: .leading, spacing: 9) {
                            securitySetting("Port", model.security.ssh.port, state: sshPortState)
                            securitySetting("Public-key auth", model.security.ssh.pubkeyAuthentication, state: model.security.ssh.pubkeyAuthentication == "yes" ? .online : .critical)
                            securitySetting("Password auth", model.security.ssh.passwordAuthentication, state: model.security.ssh.passwordAuthentication == "yes" ? .warning : .online)
                            securitySetting("Keyboard-interactive", model.security.ssh.keyboardInteractiveAuthentication, state: model.security.ssh.keyboardInteractiveAuthentication == "yes" ? .warning : .online)
                            securitySetting("Root login", model.security.ssh.permitRootLogin, state: rootLoginState)
                            securitySetting("Empty passwords", model.security.ssh.permitEmptyPasswords, state: model.security.ssh.permitEmptyPasswords == "yes" ? .critical : .online)
                            securitySetting("MaxAuthTries", model.security.ssh.maxAuthTries, state: maxAuthTriesState)
                            securitySetting("MaxSessions", model.security.ssh.maxSessions, state: .online)
                            securitySetting("X11 forwarding", model.security.ssh.x11Forwarding, state: .online)
                            securitySetting("TCP forwarding", model.security.ssh.allowTCPForwarding, state: .online)

                            if !model.security.ssh.findings.isEmpty {
                                Divider()
                                ForEach(model.security.ssh.findings, id: \.self) { finding in
                                    Label(finding, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                                }
                            }
                        }
                    }
                }

                MetricCard(title: "SSH Authentication · last 24h", icon: "person.badge.key") {
                    VStack(alignment: .leading, spacing: 8) {
                        KeyValueRow(key: "Failed / suspicious", value: String(model.security.ssh.failedLogins24h))
                        KeyValueRow(key: "Successful", value: String(model.security.ssh.successfulLogins24h))
                        KeyValueRow(key: "Last successful", value: model.security.ssh.lastSuccessfulLogin)
                        Text("Counts are read from systemd journal entries for ssh/sshd and may be incomplete if journal retention is limited.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }

                Text("Security Audit is read-only. It reads active sockets, WireGuard/OpenVPN bind metadata, effective sshd settings and recent SSH journal entries; it does not change firewall or SSH configuration.")
                    .foregroundStyle(.secondary)
            }
            .padding(20)
        }
        .task {
            if model.security.lastUpdated == nil {
                await model.refreshSecurityAudit()
            }
        }
    }

    private var securityLabel: String {
        switch model.security.state {
        case .online: return "Healthy"
        case .warning: return "Review recommended"
        case .critical: return "Critical findings"
        case .offline: return "Unavailable"
        case .unknown: return "Not audited"
        }
    }

    private var sshPortState: HealthState {
        guard let effective = Int(model.security.ssh.port) else { return .warning }
        return effective == model.settings.port ? .online : .warning
    }

    private var rootLoginState: HealthState {
        let root = model.security.ssh.permitRootLogin
        if root == "yes" && model.security.ssh.passwordAuthentication == "yes" { return .critical }
        if root == "yes" { return .warning }
        return .online
    }

    private var maxAuthTriesState: HealthState {
        guard let value = Int(model.security.ssh.maxAuthTries) else { return .warning }
        return value > 6 ? .warning : .online
    }

    private func listenerRow(_ listener: SecurityListener) -> some View {
        HStack(alignment: .top, spacing: 10) {
            StatusDot(state: listener.state)
            VStack(alignment: .leading, spacing: 2) {
                Text(listener.service).fontWeight(.semibold)
                Text("\(listener.protocolName.uppercased()) \(listener.addresses.joined(separator: ", ")):\(listener.port)")
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                Text(listener.note).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if !listener.process.isEmpty {
                Text(listener.process).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
        }
    }

    private func securitySetting(_ name: String, _ value: String, state: HealthState) -> some View {
        HStack {
            StatusDot(state: state)
            Text(name)
            Spacer()
            Text(value).font(.system(.body, design: .monospaced)).textSelection(.enabled)
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