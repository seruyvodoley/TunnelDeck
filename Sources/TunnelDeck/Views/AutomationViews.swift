import Foundation
import SwiftUI
import Charts

struct DoctorView: View {
    @EnvironmentObject var model: AppViewModel
    var body: some View {
        VStack(spacing: 0) {
            HStack { Button(model.isRunningHealthCheck ? "Checking…" : "Full Health Check") { Task { await model.runFullHealthCheck() } }.buttonStyle(.borderedProminent).disabled(model.isRunningHealthCheck || model.settings.host.isEmpty); Spacer(); if let report = model.healthReport { Label(report.state.rawValue.capitalized, systemImage: report.state == .online ? "checkmark.seal.fill" : report.state == .offline ? "wifi.slash" : "exclamationmark.triangle.fill").foregroundStyle(report.state == .online ? .green : report.state == .warning ? .orange : .red) } }.padding()
            if let report = model.healthReport {
                if report.issues.isEmpty { ContentUnavailableView("Healthy", systemImage: "checkmark.shield.fill", description: Text("All read-only health checks passed.")) }
                else { List(report.issues) { issue in DisclosureGroup { VStack(alignment: .leading) { Text(issue.technicalDetails).font(.system(.caption, design: .monospaced)).textSelection(.enabled); if issue.fix == "approve-listener" { Button("Mark as expected for this VPS") { model.approveListener(for: issue) } } else if issue.fix == "ignore-peer" { Button("Ignore this peer for health") { model.ignorePeer(for: issue) } } else if issue.fix != nil { Button("Review Fix") { model.selectedSection = .services }.disabled(issue.state == .offline) } } } label: { HStack { StatusDot(state: issue.state); VStack(alignment: .leading) { Text(issue.title).fontWeight(.semibold); Text(issue.explanation).foregroundStyle(.secondary) }; Spacer() } } } }
            } else { ContentUnavailableView("No health report", systemImage: "cross.case", description: Text("Run the full check to inspect SSH, WireGuard, routing, DNS, services, resources and firewall state.")) }
        }
    }
}

struct MonitoringView: View {
    @EnvironmentObject var model: AppViewModel

    private var filteredSamples: [MonitoringSample] {
        let cutoff = Date().addingTimeInterval(-Double(model.monitoringWindowHours) * 3600)
        return model.monitoringSamples.filter { $0.timestamp >= cutoff }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                MetricCard(title: "Background monitoring", icon: "waveform.path.ecg") {
                    VStack(alignment: .leading, spacing: 10) {
                        Toggle("Enable polling", isOn: $model.settings.pollingEnabled)
                        HStack {
                            Text("Interval")
                            Slider(value: $model.settings.pollingInterval, in: 5...300, step: 5)
                            Text("\(Int(model.settings.pollingInterval)) s").monospacedDigit()
                        }
                        Toggle("State-change notifications", isOn: $model.settings.notificationsEnabled)
                            .onChange(of: model.settings.notificationsEnabled) { _, enabled in
                                if enabled { NotificationService.request() }
                            }
                        HStack {
                            Button("Save Monitoring Settings") { model.saveSettings() }
                            Button("Reload History") { Task { await model.loadMonitoringHistory() } }
                            Spacer()
                            Text("History is stored locally on this Mac.").foregroundStyle(.secondary)
                        }
                    }
                }

                LazyVGrid(columns: [GridItem(.adaptive(minimum: 210), spacing: 12)], spacing: 12) {
                    serviceCard("VPS", component: "vps", state: model.system.health)
                    serviceCard("WireGuard wg0", component: "wg0", state: model.wireGuard.state)
                    serviceCard("AdGuard", component: "adguard", state: latestSample?.adGuardState ?? .unknown)
                    serviceCard("AntiZapret", component: "antizapret", state: latestSample?.antiZapretState ?? .unknown)
                }

                MetricCard(title: "History", icon: "chart.xyaxis.line") {
                    VStack(alignment: .leading, spacing: 12) {
                        Picker("Window", selection: $model.monitoringWindowHours) {
                            Text("1 hour").tag(1)
                            Text("6 hours").tag(6)
                            Text("24 hours").tag(24)
                        }
                        .pickerStyle(.segmented)
                        .frame(maxWidth: 420)

                        if filteredSamples.isEmpty {
                            Text("No samples in this window yet. Keep polling enabled to build history.")
                                .foregroundStyle(.secondary)
                                .frame(maxWidth: .infinity, minHeight: 160, alignment: .center)
                        } else {
                            HStack(spacing: 24) {
                                averageMetric("CPU avg", filteredSamples.map(\.cpuPercent))
                                averageMetric("RAM avg", filteredSamples.map(\.memoryPercent))
                                averageMetric("Disk avg", filteredSamples.map(\.diskPercent))
                                averageMetric("Ping avg", filteredSamples.compactMap(\.pingMilliseconds), suffix: " ms")
                            }

                            Chart(filteredSamples) { sample in
                                LineMark(x: .value("Time", sample.timestamp), y: .value("Percent", sample.cpuPercent))
                                    .foregroundStyle(by: .value("Metric", "CPU"))
                                LineMark(x: .value("Time", sample.timestamp), y: .value("Percent", sample.memoryPercent))
                                    .foregroundStyle(by: .value("Metric", "RAM"))
                                LineMark(x: .value("Time", sample.timestamp), y: .value("Percent", sample.diskPercent))
                                    .foregroundStyle(by: .value("Metric", "Disk"))
                            }
                            .chartYScale(domain: 0...100)
                            .chartLegend(position: .bottom)
                            .frame(height: 230)

                            let pingSamples = filteredSamples.filter { $0.pingMilliseconds != nil }
                            if !pingSamples.isEmpty {
                                Text("VPS internet latency").font(.headline)
                                Chart(pingSamples) { sample in
                                    LineMark(
                                        x: .value("Time", sample.timestamp),
                                        y: .value("Ping", sample.pingMilliseconds ?? 0)
                                    )
                                }
                                .frame(height: 150)
                            }
                        }
                    }
                }

                MetricCard(title: "Event log", icon: "clock.arrow.circlepath") {
                    VStack(alignment: .leading, spacing: 10) {
                        if model.monitoringEvents.isEmpty {
                            Text("No state transitions recorded yet.").foregroundStyle(.secondary)
                        } else {
                            ForEach(Array(model.monitoringEvents.suffix(100).reversed())) { event in
                                HStack(alignment: .top, spacing: 10) {
                                    StatusDot(state: event.state)
                                    Text(event.timestamp.formatted(date: .abbreviated, time: .standard))
                                        .font(.system(.caption, design: .monospaced))
                                        .frame(width: 150, alignment: .leading)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(event.title).fontWeight(.semibold)
                                        Text(event.detail).font(.caption).foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                }
                                Divider()
                            }
                        }
                    }
                }

                MetricCard(title: "Peer inactivity", icon: "network") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Peers are marked offline after \(Int(model.settings.handshakeTimeout)) seconds without a handshake. Configure the threshold in Settings.")
                            .foregroundStyle(.secondary)
                        if !model.ignoredPeerIDs.isEmpty {
                            HStack {
                                Text("Ignored by Doctor")
                                Spacer()
                                Text("\(model.ignoredPeerIDs.count)").foregroundStyle(.secondary)
                                Button("Reset") { model.resetIgnoredPeers() }
                            }
                        }
                    }
                }
            }
            .padding(20)
        }
    }

    private var latestSample: MonitoringSample? { model.monitoringSamples.last }

    private func serviceCard(_ title: String, component: String, state: HealthState) -> some View {
        MetricCard(title: title, icon: "circle.grid.2x2") {
            VStack(alignment: .leading, spacing: 7) {
                HStack {
                    StatusDot(state: state)
                    Text(state.rawValue.capitalized).font(.title3.bold())
                }
                KeyValueRow(key: "Current streak", value: currentStreak(component))
                KeyValueRow(key: "Changes · 24h", value: String(changes24h(component)))
            }
        }
    }

    private func currentStreak(_ component: String) -> String {
        guard let firstSample = model.monitoringSamples.first else { return "—" }
        let since = model.monitoringEvents.last(where: { $0.component == component })?.timestamp ?? firstSample.timestamp
        return durationString(Date().timeIntervalSince(since))
    }

    private func changes24h(_ component: String) -> Int {
        let cutoff = Date().addingTimeInterval(-86_400)
        return model.monitoringEvents.filter { $0.component == component && $0.timestamp >= cutoff }.count
    }

    private func durationString(_ interval: TimeInterval) -> String {
        let seconds = max(0, Int(interval))
        let days = seconds / 86_400
        let hours = (seconds % 86_400) / 3_600
        let minutes = (seconds % 3_600) / 60
        if days > 0 { return "\(days)d \(hours)h" }
        if hours > 0 { return "\(hours)h \(minutes)m" }
        return "\(minutes)m"
    }

    private func averageMetric(_ title: String, _ values: [Double], suffix: String = "%") -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(values.isEmpty ? "—" : String(format: "%.0f%@", values.reduce(0, +) / Double(values.count), suffix))
                .font(.title3.bold())
                .monospacedDigit()
        }
    }
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
        Button("Open Verified Restore") { model.selectedSection = .backups }
        Text("Verified restore is available from Backups: choose a backup, select the restore type, review the SHA-256/diff preview, then restore with rollback protection.").font(.caption).foregroundStyle(.secondary)
    }.padding(20) } }
}