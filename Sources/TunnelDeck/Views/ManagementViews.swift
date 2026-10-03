import SwiftUI

struct LogViewer: View {
    @EnvironmentObject var model: AppViewModel
    private var safeLog: String {
        model.logs.map { "[\($0.timestamp.formatted())] \($0.subsystem)\n$ \($0.command)\n\($0.stdout)\($0.stderr)\nexit=\($0.exitCode)" }.joined(separator: "\n\n")
    }
    var body: some View {
        VStack {
            HStack {
                Text("All content is redacted before storage and display.").foregroundStyle(.secondary)
                Spacer()
                Button("Copy Safe Log") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(SecretRedactor.redact(safeLog), forType: .string)
                }
            }.padding()
            List(model.logs) { entry in
                DisclosureGroup {
                    VStack(alignment: .leading) {
                        if !entry.stdout.isEmpty { Text(entry.stdout).font(.system(.caption, design: .monospaced)).textSelection(.enabled) }
                        if !entry.stderr.isEmpty { Text(entry.stderr).font(.system(.caption, design: .monospaced)).foregroundStyle(.red).textSelection(.enabled) }
                    }.padding(.vertical, 6)
                } label: {
                    HStack {
                        Text(entry.timestamp.formatted(date: .omitted, time: .standard)).monospacedDigit()
                        Text(entry.subsystem).fontWeight(.semibold)
                        Text(entry.command).foregroundStyle(.secondary).lineLimit(1)
                        Spacer()
                        Text("exit \(entry.exitCode)").foregroundStyle(entry.exitCode == 0 ? .green : .red)
                    }
                }
            }
        }
    }
}

struct SettingsView: View {
    @EnvironmentObject var model: AppViewModel
    @StateObject private var state = SettingsScreenState()
    var body: some View {
        Form {
            Section("Connection") {
                TextField("VPS host", text: $model.settings.host)
                TextField("SSH port", value: $model.settings.port, format: .number)
                TextField("SSH username", text: $model.settings.username)
                TextField("Private key path", text: $model.settings.keyPath)
                HStack { Button("Test SSH") { Task { _ = await model.testSSH() } }; Text(model.statusMessage).foregroundStyle(.secondary) }
            }
            Section("Servers") {
                if !model.servers.isEmpty {
                    Picker("Active VPS", selection: Binding(get: { model.activeServerID }, set: { if let id = $0 { model.selectServer(id) } })) {
                        Text("Select server").tag(UUID?.none)
                        ForEach(model.servers) { server in Text("\(server.name) · \(server.role)").tag(Optional(server.id)) }
                    }
                }
                Button("Save Current as Primary VPS") { model.saveCurrentServer() }.disabled(model.settings.host.isEmpty)
                Text("Servers are stored separately. TunnelDeck never copies or migrates configuration between VPS instances.").foregroundStyle(.secondary)
            }
            Section("Polling") {
                Toggle("Enable polling", isOn: $model.settings.pollingEnabled)
                HStack { Text("Interval"); Slider(value: $model.settings.pollingInterval, in: 5...300, step: 5); Text("\(Int(model.settings.pollingInterval)) s") }
                HStack { Text("Peer online timeout"); Slider(value: $model.settings.handshakeTimeout, in: 60...600, step: 30); Text("\(Int(model.settings.handshakeTimeout)) s") }
            }
            Section("Safety") {
                Label("READ-ONLY MODE — ALWAYS ON", systemImage: "lock.fill").foregroundStyle(.green)
                Toggle("Enable Write Mode", isOn: Binding(get: { model.settings.writeModeEnabled }, set: { enabled in
                    if enabled { state.confirmWriteMode = true } else { model.settings.writeModeEnabled = false; model.saveSettings() }
                }))
                Text("Write Mode only permits validated TunnelDeck helper subcommands. Automatic backups are required before configuration changes.").foregroundStyle(.secondary)
                if let version = model.helperVersion { KeyValueRow(key: "Legacy Helper", value: "\(version) · Ready") }
                else { Label("Legacy Helper unavailable", systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
                if let helper2 = model.helper2Capabilities { KeyValueRow(key: "Helper 2", value: "\(helper2.version) · Ready") }
                else { KeyValueRow(key: "Helper 2", value: "Not installed") }
            }
            Section("System") {
                Toggle("Launch at Login", isOn: Binding(get: { model.settings.launchAtLogin }, set: { value in
                    do { try LaunchAtLoginService.setEnabled(value); model.settings.launchAtLogin = value; model.saveSettings() }
                    catch { model.presentedError = AppError(title: "Launch at Login failed", message: "macOS could not update the login-item setting.", technicalDetails: error.localizedDescription, recommendedAction: "Open System Settings → General → Login Items and verify permission.") }
                }))
                Toggle("State-change notifications", isOn: $model.settings.notificationsEnabled).onChange(of: model.settings.notificationsEnabled) { _, enabled in if enabled { NotificationService.request() } }
            }
            #if DEBUG
            Section("Diagnostics (DEBUG)") {
                KeyValueRow(key:"Active node",value:model.activeServerID.map{String($0.uuidString.prefix(8))+"…"} ?? "None")
                KeyValueRow(key:"Polling",value:"\(model.debugPollingRunning ? "Running":"Stopped") · generation \(model.debugPollingGeneration)")
                KeyValueRow(key:"Last refresh",value:model.lastRefreshDuration.map{String(format:"%.2f s",$0)} ?? "Never")
                KeyValueRow(key:"Last Agent sync",value:model.lastAgentSyncAt?.formatted() ?? "Never")
                KeyValueRow(key:"Loaded rows",value:"samples \(model.monitoringSamples.count), events \(model.monitoringEvents.count), peers \(model.peerHistory.count), DNS \(model.adGuardHistory.count)")
                KeyValueRow(key:"SQLite schema",value:model.sqliteSchemaVersion.map(String.init) ?? "Unavailable")
                KeyValueRow(key:"Agent cursors",value:"S \(model.agentCursors.samples), E \(model.agentCursors.events), P \(model.agentCursors.peers), D \(model.agentCursors.adGuard)")
                if let error=model.persistenceErrorMessage{Text(error).foregroundStyle(.orange).textSelection(.enabled)}
            }
            #endif
            Button("Save") { model.saveSettings() }
        }.formStyle(.grouped).padding()
            .alert("Enable Write Mode?", isPresented: $state.confirmWriteMode) {
                Button("Cancel", role: .cancel) {}
                Button("Enable", role: .destructive) { model.settings.writeModeEnabled = true; model.saveSettings() }
            } message: {
                Text("Write Mode allows TunnelDeck to change configuration on the VPS. Automatic backups will be created before every configuration change.")
            }
    }
}

@MainActor
private final class SettingsScreenState: ObservableObject { @Published var confirmWriteMode = false }

struct OnboardingView: View {
    @EnvironmentObject var model: AppViewModel
    @StateObject private var state = OnboardingState()
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack {
                Image(systemName: "lock.shield.fill").font(.system(size: 42)).foregroundStyle(Color.accentColor)
                VStack(alignment: .leading) { Text("Welcome to TunnelDeck").font(.largeTitle.bold()); Text("Read-only infrastructure monitoring") }
            }
            ProgressView(value: Double(state.step + 1), total: 5)
            stepContent.frame(maxWidth: .infinity, minHeight: 180, alignment: .topLeading)
            HStack {
                Button("Back") { state.step -= 1 }.disabled(state.step == 0)
                Spacer()
                Button(state.step == 4 ? "Open Dashboard" : "Continue") {
                    if state.step == 4 { model.completeOnboarding() } else { state.step += 1 }
                }.buttonStyle(.borderedProminent)
            }
        }.padding(30).frame(width: 640, height: 430).interactiveDismissDisabled()
    }

    @ViewBuilder private var stepContent: some View {
        switch state.step {
        case 0:
            VStack(alignment: .leading) { Text("VPS").font(.title2.bold()); TextField("VPS IP or hostname", text: $model.settings.host) }
        case 1:
            VStack(alignment: .leading) { Text("SSH identity").font(.title2.bold()); TextField("Username", text: $model.settings.username); TextField("Private key path", text: $model.settings.keyPath); Text("The path is stored in macOS Keychain. Passwords are not supported or stored.").foregroundStyle(.secondary) }
        case 2:
            VStack(alignment: .leading) { Text("Test SSH").font(.title2.bold()); Button(state.testing ? "Testing…" : "Run uname -a") { state.testing = true; Task { _ = await model.testSSH(); state.testing = false } }.disabled(state.testing); Text(model.statusMessage).foregroundStyle(.secondary) }
        case 3:
            VStack(alignment: .leading) { Text("Discover infrastructure").font(.title2.bold()); Text("WireGuard interfaces, systemd units, DNS listeners, AntiZapret and AdGuard Home will be queried with whitelisted read-only commands."); Button("Discover") { Task { await model.refresh() } } }
        default:
            VStack(alignment: .leading) { Text("Ready").font(.title2.bold()); Label("No server or router settings were changed", systemImage: "checkmark.seal.fill").foregroundStyle(.green); Text("Discovered: \(model.wireGuard.peers.count) WireGuard peers, \(model.units.count) units, \(model.listeners.count) listeners.") }
        }
    }
}

@MainActor
private final class OnboardingState: ObservableObject {
    @Published var step = 0
    @Published var testing = false
}

struct MenuBarView: View {
    @EnvironmentObject var model: AppViewModel
    private var latestAge: String { model.wireGuard.peers.compactMap(\.latestHandshake).max()?.formatted(.relative(presentation: .numeric)) ?? "Never" }
    var body: some View {
        VStack(alignment: .leading) {
            Label { Text("VPS \(model.system.health.rawValue)") } icon: { StatusDot(state: model.system.health) }
            Label { Text("WG \(model.wireGuard.state.rawValue)") } icon: { StatusDot(state: model.wireGuard.state) }
            Text("Peers: \(model.wireGuard.peers.count)")
            Text("Handshake: \(latestAge)")
            Divider()
            Button("Open Dashboard") { NSApp.activate(ignoringOtherApps: true); model.selectedSection = .dashboard }
            Button("Refresh") { Task { await model.refresh() } }
            Button("Test Connection") { Task { _ = await model.testSSH() } }
            Button("Open Router Settings") { NSApp.activate(ignoringOtherApps: true); model.selectedSection = .router }
            Button("Open AdGuard") { if let url = model.discoveredAdGuardBaseURL() { LocalNetworkService.open(url) } }.disabled(model.discoveredAdGuardBaseURL() == nil)
            Button("Restart WG") {}.disabled(true)
            Divider()
            Button("Quit") { NSApp.terminate(nil) }
        }.padding(6)
    }
}
