import SwiftUI

struct DashboardView: View {
    @EnvironmentObject var model: AppViewModel
    private let columns = [GridItem(.adaptive(minimum: 290), spacing: 16)]

    var body: some View {
        ScrollView {
            LazyVGrid(columns: columns, alignment: .leading, spacing: 16) {
                MetricCard(title: "Overall Health", icon: "heart.text.square") {
                    VStack(spacing: 8) {
                        HStack { StatusDot(state: model.healthReport?.state ?? .unknown); Text(model.healthReport?.state.rawValue.capitalized ?? "Not checked").font(.title3.bold()); Spacer() }
                        KeyValueRow(key: "Last successful check", value: model.lastSuccessfulHealthCheck?.formatted() ?? "Never")
                        KeyValueRow(key: "Critical alerts", value: String(model.healthReport?.issues.filter { $0.state == .critical }.count ?? 0))
                        KeyValueRow(key: "Config drift", value: model.configurationDrift.isEmpty ? "None detected" : "\(model.configurationDrift.count) changed")
                        Button("Full Health Check") { Task { await model.runFullHealthCheck() } }.disabled(model.isRunningHealthCheck)
                    }
                }

                MetricCard(title: "VPS", icon: "server.rack") {
                    VStack(spacing: 8) {
                        HStack { StatusDot(state: model.system.health); Text(model.system.hostname).font(.title3.bold()); Spacer(); Text(model.system.sshAvailable ? "SSH" : "No SSH").foregroundStyle(.secondary) }
                        KeyValueRow(key: "OS", value: model.system.osVersion)
                        KeyValueRow(key: "Kernel", value: model.system.kernel)
                        KeyValueRow(key: "Uptime", value: model.system.uptime)
                        KeyValueRow(key: "Load", value: model.system.loadAverage)
                        KeyValueRow(key: "IPv4", value: model.system.publicIPv4)
                        KeyValueRow(key: "IPv6", value: model.system.publicIPv6)
                    }
                }

                MetricCard(title: "Resources", icon: "cpu") {
                    VStack(spacing: 12) {
                        usage("Memory", model.system.memoryPercent)
                        usage("Disk", model.system.diskPercent)
                        usage("CPU", model.system.cpuPercent)
                    }
                }

                MetricCard(title: "WireGuard wg0", icon: "network") {
                    VStack(spacing: 8) {
                        HStack { StatusDot(state: model.wireGuard.state); Text(model.wireGuard.state.rawValue.capitalized); Spacer(); Text("\(model.wireGuard.peers.count) peers") }
                        KeyValueRow(key: "Address", value: model.wireGuard.address)
                        KeyValueRow(key: "Listen port", value: model.wireGuard.listenPort)
                        KeyValueRow(key: "MTU", value: model.wireGuard.mtu)
                        KeyValueRow(key: "Public key", value: model.wireGuard.publicKey)
                        KeyValueRow(key: "Transfer", value: "↓ \(model.wireGuard.receivedBytes.byteString)  ↑ \(model.wireGuard.sentBytes.byteString)")
                    }
                }

                MetricCard(title: "Services", icon: "gearshape.2") {
                    VStack(alignment: .leading, spacing: 7) {
                        ForEach(model.units.prefix(7)) { unit in
                            HStack { StatusDot(state: unit.health); Text(unit.name).lineLimit(1); Spacer(); Text(unit.activeState).foregroundStyle(.secondary) }
                        }
                    }
                }

                MetricCard(title: "This Mac", icon: "laptopcomputer") {
                    VStack(spacing: 8) {
                        KeyValueRow(key: "LAN IPv4", value: model.system.macLANIP)
                        KeyValueRow(key: "Public IP", value: model.system.macPublicIP)
                        KeyValueRow(key: "VPS target", value: model.settings.host)
                    }
                }

                MetricCard(title: "Safety", icon: "lock.shield") {
                    VStack(alignment: .leading, spacing: 8) {
                        Label(model.settings.writeModeEnabled ? "Write Mode enabled" : "Read-only by default", systemImage: model.settings.writeModeEnabled ? "exclamationmark.shield.fill" : "checkmark.seal.fill")
                            .foregroundStyle(model.settings.writeModeEnabled ? .orange : .green)
                        Text("Write operations are restricted to the versioned server helper, explicit confirmation, scoped backups and validation. Package and OS upgrades are never automatic.")
                            .foregroundStyle(.secondary)
                    }
                }

                gatewayCard
                homeUplinkCard
                tunnelCard(model.homeInfrastructure.foreignTunnel, fallbackTitle: "Foreign Tunnel", fallbackRole: "Foreign Exit")
                tunnelCard(model.homeInfrastructure.homeExitTunnel, fallbackTitle: "Home Exit", fallbackRole: "Remote RU Home Exit")
                tunnelCard(model.homeInfrastructure.managementTunnel, fallbackTitle: "Management Tunnel", fallbackRole: "Remote Home LAN Management")
            }
            .padding(20)
        }
        .overlay { if model.isRefreshing { ProgressView().controlSize(.large) } }
    }

    private var gatewayCard: some View {
        let gateway=model.homeInfrastructure.gateway
        return MetricCard(title: "TunnelDeck Gateway", icon: "point.3.connected.trianglepath.dotted") {
            VStack(spacing: 8) {
                HStack {
                    StatusDot(state: gateway.state)
                    Text(gateway.hostname ?? gateway.host ?? "OpenWrt").font(.title3.bold())
                    Spacer()
                    Text(gateway.state.rawValue.capitalized).foregroundStyle(.secondary)
                }
                KeyValueRow(key: "Role", value: "Policy Router / DHCP / DNS")
                KeyValueRow(key: "LAN", value: gateway.lanIPv4 ?? gateway.host ?? "Unknown")
                KeyValueRow(key: "OpenWrt", value: gateway.version ?? "Unknown")
                KeyValueRow(key: "Default via", value: [gateway.defaultGateway,gateway.defaultInterface].compactMap{$0}.joined(separator:" · ").nonEmpty ?? "Unknown")
                KeyValueRow(key: "DHCP / DNS", value: "\(boolText(gateway.dhcpServer)) / \(boolText(gateway.dnsServer))")
                KeyValueRow(key: "RU prefixes", value: gateway.ruPrefixCount.map(String.init) ?? "Unknown")
                KeyValueRow(key: "Last discovery", value: gateway.observedAt?.formatted(.relative(presentation:.numeric)) ?? "Never")
            }
        }
    }

    private var homeUplinkCard: some View {
        let routerIP=model.home.network?.routerIP.nonEmpty ?? "Unknown"
        return MetricCard(title: "Home Uplink", icon: "wifi.router") {
            VStack(spacing: 8) {
                HStack { StatusDot(state: uplinkState); Text("TP-Link Archer AX18").font(.title3.bold()); Spacer(); Text(uplinkState.rawValue.capitalized).foregroundStyle(.secondary) }
                KeyValueRow(key: "Role", value: "Home Uplink / ISP Gateway")
                KeyValueRow(key: "Address", value: routerIP)
                KeyValueRow(key: "Gateway from Xiaomi", value: model.homeInfrastructure.gateway.defaultGateway ?? "Unknown")
                KeyValueRow(key: "Inventory", value: model.home.routerState.rawValue)
                KeyValueRow(key: "Path", value: model.homeInfrastructure.directPathConfirmed ? "DIRECT route observed" : "Not confirmed")
            }
        }
    }

    private func tunnelCard(_ tunnel: InfrastructureTunnelSnapshot?, fallbackTitle:String, fallbackRole:String) -> some View {
        let state=tunnel?.state ?? .unknown
        return MetricCard(title: tunnel?.name ?? fallbackTitle, icon: "network") {
            VStack(spacing: 8) {
                HStack { StatusDot(state: state); Text(tunnel?.transport ?? "Tunnel").font(.title3.bold()); Spacer(); Text(state.rawValue.capitalized).foregroundStyle(.secondary) }
                KeyValueRow(key: "Role", value: tunnel?.role ?? fallbackRole)
                KeyValueRow(key: "Address", value: tunnel?.localAddress ?? "Unknown")
                KeyValueRow(key: "Peer", value: tunnel?.peerAddress ?? "Unknown")
                KeyValueRow(key: "Endpoint", value: tunnel?.endpoint ?? "Unknown")
                KeyValueRow(key: "MTU", value: tunnel?.mtu.map(String.init) ?? "Unknown")
                KeyValueRow(key: "Handshake", value: tunnel?.latestHandshake?.formatted(.relative(presentation:.numeric)) ?? "Unknown")
                KeyValueRow(key: "Transfer", value: tunnel.map{"↓ \($0.receivedBytes.byteString)  ↑ \($0.sentBytes.byteString)"} ?? "Unknown")
            }
        }
    }

    private var uplinkState:HealthState {
        if model.home.routerState == .connected { return .online }
        guard let ip=model.home.network?.routerIP else{return .unknown}
        if let device=model.home.devices.first(where:{$0.ipv4==ip}) {
            switch device.status { case .online:return .online;case .offline:return .offline;case .unknown:return .unknown }
        }
        return .unknown
    }

    private func boolText(_ value:Bool?)->String{value.map{$0 ? "Active":"Inactive"} ?? "Unknown"}

    private func usage(_ title: String, _ value: Double) -> some View {
        VStack(alignment: .leading) {
            HStack { Text(title); Spacer(); Text(value, format: .number.precision(.fractionLength(0))).monospacedDigit(); Text("%") }
            ProgressView(value: min(value, 100), total: 100).tint(value > 90 ? .red : value > 75 ? .yellow : .accentColor)
        }
    }
}

private extension String {
    var nonEmpty:String?{isEmpty ? nil:self}
}
