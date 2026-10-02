import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var model: AppViewModel
    private let columns = [GridItem(.adaptive(minimum: 290), spacing: 16)]
    var body: some View {
        ScrollView { LazyVGrid(columns: columns, alignment: .leading, spacing: 16) {
            MetricCard(title: "VPS", icon: "server.rack") { VStack(spacing: 8) { HStack { StatusDot(state: model.system.health); Text(model.system.hostname).font(.title3.bold()); Spacer(); Text(model.system.sshAvailable ? "SSH" : "No SSH").foregroundStyle(.secondary) }; KeyValueRow(key: "OS", value: model.system.osVersion); KeyValueRow(key: "Kernel", value: model.system.kernel); KeyValueRow(key: "Uptime", value: model.system.uptime); KeyValueRow(key: "Load", value: model.system.loadAverage); KeyValueRow(key: "IPv4", value: model.system.publicIPv4); KeyValueRow(key: "IPv6", value: model.system.publicIPv6) } }
            MetricCard(title: "Resources", icon: "cpu") { VStack(spacing: 12) { usage("Memory", model.system.memoryPercent); usage("Disk", model.system.diskPercent); usage("CPU", model.system.cpuPercent) } }
            MetricCard(title: "WireGuard wg0", icon: "network") { VStack(spacing: 8) { HStack { StatusDot(state: model.wireGuard.state); Text(model.wireGuard.state.rawValue.capitalized); Spacer(); Text("\(model.wireGuard.peers.count) peers") }; KeyValueRow(key: "Address", value: model.wireGuard.address); KeyValueRow(key: "Listen port", value: model.wireGuard.listenPort); KeyValueRow(key: "MTU", value: model.wireGuard.mtu); KeyValueRow(key: "Public key", value: model.wireGuard.publicKey); KeyValueRow(key: "Transfer", value: "↓ \(model.wireGuard.receivedBytes.byteString)  ↑ \(model.wireGuard.sentBytes.byteString)") } }
            MetricCard(title: "Services", icon: "gearshape.2") { VStack(alignment: .leading, spacing: 7) { ForEach(model.units.prefix(7)) { unit in HStack { StatusDot(state: unit.health); Text(unit.name).lineLimit(1); Spacer(); Text(unit.activeState).foregroundStyle(.secondary) } } } }
            MetricCard(title: "This Mac", icon: "laptopcomputer") { VStack(spacing: 8) { KeyValueRow(key: "LAN IPv4", value: model.system.macLANIP); KeyValueRow(key: "Public IP", value: model.system.macPublicIP); KeyValueRow(key: "VPS target", value: model.settings.host) } }
            MetricCard(title: "Safety", icon: "lock.shield") { VStack(alignment: .leading, spacing: 8) { Label("Read-only mode is always enabled", systemImage: "checkmark.seal.fill").foregroundStyle(.green); Text("No restart, file modification, firewall, package or WireGuard mutation commands exist in the command policy.").foregroundStyle(.secondary) } }
        }.padding(20) }.overlay { if model.isRefreshing { ProgressView().controlSize(.large) } }
    }
    private func usage(_ title: String, _ value: Double) -> some View { VStack(alignment: .leading) { HStack { Text(title); Spacer(); Text(value, format: .number.precision(.fractionLength(0))).monospacedDigit(); Text("%") }; ProgressView(value: min(value, 100), total: 100).tint(value > 90 ? .red : value > 75 ? .yellow : .accentColor) } }
}
