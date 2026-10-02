import SwiftUI

struct DoctorView: View {
    @EnvironmentObject var model: AppViewModel
    var body: some View {
        VStack(spacing: 0) {
            HStack { Button(model.isRunningHealthCheck ? "Checking…" : "Full Health Check") { Task { await model.runFullHealthCheck() } }.buttonStyle(.borderedProminent).disabled(model.isRunningHealthCheck || model.settings.host.isEmpty); Spacer(); if let report = model.healthReport { Label(report.state.rawValue.capitalized, systemImage: report.state == .online ? "checkmark.seal.fill" : "exclamationmark.triangle.fill").foregroundStyle(report.state == .online ? .green : report.state == .warning ? .orange : .red) } }.padding()
            if let report = model.healthReport {
                if report.issues.isEmpty { ContentUnavailableView("Healthy", systemImage: "checkmark.shield.fill", description: Text("All read-only health checks passed.")) }
                else { List(report.issues) { issue in DisclosureGroup { VStack(alignment: .leading) { Text(issue.technicalDetails).font(.system(.caption, design: .monospaced)).textSelection(.enabled); if issue.fix == "approve-listener" { Button("Mark as expected for this VPS") { model.approveListener(for: issue) } } else if issue.fix != nil { Button("Review Fix") { model.selectedSection = .services }.disabled(issue.state == .offline) } } } label: { HStack { StatusDot(state: issue.state); VStack(alignment: .leading) { Text(issue.title).fontWeight(.semibold); Text(issue.explanation).foregroundStyle(.secondary) }; Spacer() } } } }
            } else { ContentUnavailableView("No health report", systemImage: "cross.case", description: Text("Run the full check to inspect SSH, WireGuard, routing, DNS, services, resources and firewall state.")) }
        }
    }
}

struct MonitoringView: View {
    @EnvironmentObject var model: AppViewModel
    var body: some View { Form {
        Section("Background monitoring") { Toggle("Enable polling", isOn: $model.settings.pollingEnabled); HStack { Text("Interval"); Slider(value: $model.settings.pollingInterval, in: 5...300, step: 5); Text("\(Int(model.settings.pollingInterval)) s") }; Toggle("Notify only on state changes", isOn: $model.settings.notificationsEnabled).onChange(of: model.settings.notificationsEnabled) { _, enabled in if enabled { NotificationService.request() } }; Button("Save Monitoring Settings") { model.saveSettings() } }
        Section("Current state") { KeyValueRow(key: "VPS", value: model.system.health.rawValue); KeyValueRow(key: "wg0", value: model.wireGuard.state.rawValue); KeyValueRow(key: "Disk", value: "\(Int(model.system.diskPercent))%"); KeyValueRow(key: "Public DNS", value: model.listeners.contains { $0.isPublic && $0.port == 53 } ? "Exposed" : "Not detected") }
        Section("Peer inactivity") { Text("Peers are marked offline after \(Int(model.settings.handshakeTimeout)) seconds without a handshake. Configure the threshold in Settings.").foregroundStyle(.secondary) }
    }.formStyle(.grouped) }
}

struct ActivityView: View {
    @EnvironmentObject var model: AppViewModel
    var body: some View { Table(model.activity.reversed()) { TableColumn("Timestamp") { Text($0.timestamp.formatted()) }; TableColumn("Operation", value: \.operation); TableColumn("Server", value: \.server); TableColumn("Result", value: \.result) } }
}

struct RecoveryView: View {
    @EnvironmentObject var model: AppViewModel
    var body: some View { ScrollView { VStack(alignment: .leading, spacing: 16) {
        Text("Recovery Mode").font(.title2.bold())
        ForEach([("WireGuard down", "Verify wg-quick@wg0, interface address and the latest known-good wg0.conf."), ("AdGuard broken", "Inspect its scoped YAML backup and bind addresses without changing AntiZapret DNS."), ("AntiZapret broken", "Restart only the detected failing unit; never replace clean wg0."), ("Helper broken", "Compare helper SHA-256 and reinstall the reviewed matching version.")], id: \.0) { scenario in MetricCard(title: scenario.0, icon: "lifepreserver") { Text(scenario.1).foregroundStyle(.secondary) } }
        Text("Latest backups").font(.headline)
        ForEach(model.backups.prefix(5)) { backup in HStack { Text(backup.timestamp); Text(backup.operation).foregroundStyle(.secondary); Spacer(); Text(backup.path).font(.caption).textSelection(.enabled) } }
        Button("Restore Last Known Good") {}.disabled(true)
        Text("Restore is disabled until server-side diff preview and automatic rollback validation are available. TunnelDeck never performs an unverified restore.").font(.caption).foregroundStyle(.secondary)
    }.padding(20) } }
}
