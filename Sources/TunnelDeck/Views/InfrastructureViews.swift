import AppKit
import SwiftUI
import Charts

struct WireGuardView: View {
    @EnvironmentObject var model: AppViewModel
    @StateObject private var state = WireGuardScreenState()
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("wg0 · \(model.wireGuard.address) · MTU \(model.wireGuard.mtu)").foregroundStyle(.secondary)
                Spacer()
                Button("Add Peer") { state.prepare(using: model); state.showAdd = true }.disabled(!canWrite)
                Button("Remove") { state.showRemove = true }.disabled(!canWrite || state.selection.count != 1)
                Button("Restart") {}.disabled(true).help("Requires a dedicated confirmed service transaction")
            }.padding()
            Table(model.wireGuard.peers, selection: $state.selection) {
                TableColumn("Name", value: \.name)
                TableColumn("VPN IP", value: \.vpnIP)
                TableColumn("Public Key", value: \.publicKey)
                TableColumn("Endpoint", value: \.endpoint)
                TableColumn("Handshake") { peer in Text(peer.latestHandshake?.formatted(.relative(presentation: .numeric)) ?? "Never") }
                TableColumn("RX") { peer in Text(peer.receivedBytes.byteString) }
                TableColumn("TX") { peer in Text(peer.sentBytes.byteString) }
                TableColumn("Status") { peer in HStack { StatusDot(state: peer.status); Text(peer.status.rawValue.capitalized) } }
                TableColumn("Managed") { peer in Text(model.managedPeers.first(where: { $0.publicKey == peer.id })?.managedBy ?? "Existing") }
            }
        }
        .sheet(isPresented: $state.showAdd) { AddPeerSheet(state: state) { Task { if await model.addPeer(name: state.name, ip: state.ip, dns: state.dns, mtu: state.mtu, allowedIPs: state.allowedIPs, endpoint: state.endpoint) { state.showAdd = false } } } }
        .alert("Remove WireGuard peer?", isPresented: $state.showRemove) {
            Button("Cancel", role: .cancel) {}
            Button("Remove peer", role: .destructive) { if let key = state.selection.first { Task { _ = await model.removePeer(publicKey: key, deleteClient: state.deleteClient, allowExisting: model.managedPeers.first(where: { $0.publicKey == key }) == nil) } } }
        } message: { Text("TunnelDeck will create a backup, remove the exact public key from wg0.conf and the live interface, then run a health check. Existing peers require elevated confirmation.") }
    }
    private var canWrite: Bool { model.settings.writeModeEnabled && model.helperCanUseLegacyWrites }
}

@MainActor
final class WireGuardScreenState: ObservableObject {
    @Published var selection = Set<String>(); @Published var showAdd = false; @Published var showRemove = false
    @Published var name = ""; @Published var ip = ""; @Published var dns = "1.1.1.1"; @Published var mtu = 1380; @Published var allowedIPs = "0.0.0.0/0"; @Published var endpoint = ""; @Published var deleteClient = false
    @Published var deviceTemplate = "Generic"; @Published var routingTemplate = "FULL"
    func prepare(using model: AppViewModel) {
        ip = model.suggestedPeerIP()
        let serverIP = model.wireGuard.address.split(separator: "/").first.map(String.init) ?? ""
        dns = model.listeners.contains { $0.address == serverIP && $0.port == 53 } ? serverIP : "1.1.1.1"
        endpoint = model.settings.host.isEmpty ? "" : "\(model.settings.host):\(model.wireGuard.listenPort == "—" ? "51820" : model.wireGuard.listenPort)"
    }
    func applyRoutingTemplate(serverIP: String) {
        allowedIPs = "0.0.0.0/0"
        if routingTemplate == "FULL + ADGUARD", !serverIP.isEmpty { dns = serverIP }
        else if routingTemplate == "FULL" { dns = "1.1.1.1" }
    }
}

struct AddPeerSheet: View {
    @ObservedObject var state: WireGuardScreenState
    let create: () -> Void
    var body: some View { VStack(alignment: .leading, spacing: 16) { Text("Add WireGuard Peer").font(.title.bold()); Form { Picker("Device", selection: $state.deviceTemplate) { ForEach(["MacBook", "iPhone", "Android", "Router", "Generic"], id: \.self) { Text($0) } }; Picker("Routing", selection: $state.routingTemplate) { ForEach(["FULL", "FULL + ADGUARD", "CUSTOM / SPLIT"], id: \.self) { Text($0) } }.onChange(of: state.routingTemplate) { _, _ in let parts = state.ip.split(separator: "."); let serverIP = parts.count == 4 ? parts.prefix(3).joined(separator: ".") + ".1" : ""; state.applyRoutingTemplate(serverIP: serverIP) }; TextField("Name", text: $state.name); TextField("VPN IP", text: $state.ip); TextField("DNS", text: $state.dns); TextField("MTU", value: $state.mtu, format: .number); TextField("AllowedIPs", text: $state.allowedIPs).disabled(state.routingTemplate != "CUSTOM / SPLIT"); TextField("Endpoint", text: $state.endpoint) }; Text("A backup is created first. wg0 is updated live without restart. Client secrets are saved locally with mode 0600 and never logged.").foregroundStyle(.secondary); HStack { Spacer(); Button("Cancel") { state.showAdd = false }; Button("Create Peer", action: create).buttonStyle(.borderedProminent).disabled(state.name.isEmpty || state.ip.isEmpty || state.endpoint.isEmpty) } }.padding(24).frame(width: 560) }
}

struct ProfilesView: View {
    @EnvironmentObject var model: AppViewModel
    @StateObject private var state = ProfileScreenState()
    var body: some View { VSplitView { VStack(alignment: .leading) { Text("Local Profiles").font(.headline).padding([.top,.leading]); Table(model.localProfiles, selection: $state.selection) { TableColumn("Name", value: \.name); TableColumn("Type", value: \.type); TableColumn("Modified") { Text($0.modified.formatted()) }; TableColumn("Actions") { profile in HStack { Button("Reveal") { ProfileStore.reveal(profile) }; Button("Open With…") { ProfileStore.open(profile) }; Button("QR") { state.showQR(profile) } } } }.frame(minHeight: 220) }; VStack(alignment: .leading) { Text("Server Profile Inventory").font(.headline).padding([.top,.leading]); Table(model.profiles) { TableColumn("Name", value: \.name); TableColumn("Type", value: \.type); TableColumn("Category", value: \.category); TableColumn("Modified", value: \.modified); TableColumn("Path", value: \.path) } } }.sheet(isPresented: $state.qrVisible) { if let image = state.qrImage { VStack { Text(state.qrName).font(.title2.bold()); Image(nsImage: image).interpolation(.none).resizable().frame(width: 360, height: 360); Text("QR contains private client configuration. Do not share it.").foregroundStyle(.red) }.padding() } } }
}

@MainActor private final class ProfileScreenState: ObservableObject {
    @Published var selection = Set<String>(); @Published var qrVisible = false; @Published var qrImage: NSImage?; @Published var qrName = ""
    func showQR(_ profile: LocalProfile) { guard let content = try? ProfileStore.content(profile) else { return }; qrName = profile.name; qrImage = ProfileStore.qrImage(for: content); qrVisible = qrImage != nil }
}

struct AntiZapretView: View {
    @EnvironmentObject var model: AppViewModel
    var body: some View { ScrollView { VStack(alignment: .leading, spacing: 18) { Text("Services").font(.title2.bold()); ForEach(model.units.filter { $0.name.contains("antizapret") || $0.name.contains("vpn-udp") || $0.name.contains("wg-quick@vpn") }) { unit in HStack { StatusDot(state: unit.health); Text(unit.name); Spacer(); Text("\(unit.activeState) / \(unit.subState)").foregroundStyle(.secondary) }.padding(10).background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10)) }; Text("Setup flags").font(.title2.bold()); Grid(alignment: .leading, horizontalSpacing: 30, verticalSpacing: 10) { ForEach(model.antiZapretSettings.keys.sorted(), id: \.self) { key in GridRow { Text(key).foregroundStyle(.secondary); Text(model.antiZapretSettings[key] ?? "—").textSelection(.enabled) } } }; HStack { Button("View Logs") { model.selectedSection = .logs }; Button("Restart") { Task { _ = await model.performServiceAction("restart", unit: "antizapret.service") } }.disabled(!model.settings.writeModeEnabled || !model.helperCanUseLegacyWrites); Button("Update Lists (not implemented)") {}.disabled(true) } }.padding(20).frame(maxWidth: 850, alignment: .leading) } }
}

struct DNSView: View {
    @EnvironmentObject var model: AppViewModel
    @StateObject private var state = DNSViewState()
    var dns: [Listener] { model.listeners.filter { $0.port == 53 } }
    var web: [Listener] { model.listeners.filter { $0.protocolName.lowercased().hasPrefix("tcp") && $0.port != 53 && $0.process.localizedCaseInsensitiveContains("AdGuardHome") } }

    var body: some View {
        let serverIP = model.wireGuard.address.split(separator: "/").first.map(String.init) ?? ""
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if dns.contains(where: { $0.isPublic || $0.address == model.settings.host }) {
                    Label("DNS is exposed on a public/wildcard address", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .padding()
                        .background(.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 12))
                }

                listenerCard("AntiZapret DNS", dns.filter { $0.address.hasPrefix("127.") })
                listenerCard("AdGuard Home DNS", dns.filter { $0.address == serverIP })
                listenerCard("Other DNS listeners", dns.filter { !$0.address.hasPrefix("127.") && $0.address != serverIP })
                listenerCard("AdGuard Web UI", web)

                MetricCard(title: "AdGuard Home API", icon: "chart.bar") {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack(spacing: 28) {
                            metric("Status", model.adGuard.available ? "Available" : "Unavailable")
                            metric("Queries", String(model.adGuard.totalQueries))
                            metric("Blocked", String(model.adGuard.blockedQueries))
                            metric("Blocked %", String(format: "%.1f%%", model.adGuard.blockedPercentage))
                            metric("Avg", String(format: "%.3f s", model.adGuard.averageProcessingTime))
                        }

                        HStack {
                            if model.adGuard.available {
                                Text("v\(model.adGuard.version)").foregroundStyle(.secondary)
                            } else {
                                Text(model.adGuard.error ?? "API not connected").foregroundStyle(.orange)
                            }
                            Spacer()
                            if let updated = model.adGuard.lastUpdated {
                                Text("Updated \(updated.formatted(date: .omitted, time: .standard))").foregroundStyle(.secondary)
                            }
                        }

                        HStack {
                            Button("Login") {
                                state.baseURL = model.discoveredAdGuardBaseURL() ?? ""
                                state.error = nil
                                state.showLogin = true
                            }
                            Button("Refresh API") { Task { await model.refreshAdGuardAPI() } }
                            Button("Open AdGuard") {
                                if let url = model.discoveredAdGuardBaseURL() { LocalNetworkService.open(url) }
                            }
                            .disabled(model.discoveredAdGuardBaseURL() == nil)
                        }
                    }
                }

                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                    listCard("Top queried", model.adGuard.topQueried)
                    listCard("Top blocked", model.adGuard.topBlocked)
                    listCard("Top clients", model.adGuard.topClients)
                }

                MetricCard(title: "Filters", icon: "line.3.horizontal.decrease.circle") {
                    if model.adGuard.filters.isEmpty {
                        Text("No active filters reported").foregroundStyle(.secondary)
                    } else {
                        Text(model.adGuard.filters.joined(separator: " · ")).textSelection(.enabled)
                    }
                }

                MetricCard(title: "Recent DNS queries", icon: "list.bullet.rectangle") {
                    if model.adGuard.queryLog.isEmpty {
                        Text("No query-log entries loaded").foregroundStyle(.secondary)
                    } else {
                        Table(Array(model.adGuard.queryLog.prefix(100))) {
                            TableColumn("Time") { entry in Text(displayTime(entry.time)).font(.system(.caption, design: .monospaced)) }
                            TableColumn("Domain", value: \.domain)
                            TableColumn("Client", value: \.client)
                            TableColumn("Status") { entry in
                                HStack(spacing: 6) {
                                    Image(systemName: entry.blocked ? "hand.raised.fill" : "checkmark.circle.fill")
                                        .foregroundStyle(entry.blocked ? .orange : .green)
                                    Text(entry.blocked ? "Blocked" : "Allowed")
                                }
                            }
                            TableColumn("Rule") { entry in Text(entry.rule).lineLimit(1).foregroundStyle(.secondary) }
                        }
                        .frame(minHeight: 300, maxHeight: 420)
                    }
                }
            }
            .padding(20)
        }
        .task {
            while !Task.isCancelled {
                await model.refreshAdGuardAPI()
                try? await Task.sleep(for: .seconds(15))
            }
        }
        .sheet(isPresented: $state.showLogin) {
            VStack(alignment: .leading, spacing: 14) {
                Text("AdGuard Home Login").font(.title2.bold())
                TextField("Base URL", text: $state.baseURL)
                TextField("Username", text: $state.username)
                SecureField("Password", text: $state.password)
                Text("Credentials are stored only in macOS Keychain. Authorization headers are never logged.").foregroundStyle(.secondary)
                if let error = state.error { Text(error).foregroundStyle(.red).textSelection(.enabled) }
                HStack {
                    Spacer()
                    Button("Cancel") { state.showLogin = false }.disabled(state.connecting)
                    Button(state.connecting ? "Connecting…" : "Save and Connect") {
                        let password = state.password
                        state.connecting = true
                        state.error = nil
                        Task {
                            let success = await model.saveAdGuardCredentials(baseURL: state.baseURL, username: state.username, password: password)
                            state.connecting = false
                            if success {
                                state.password = ""
                                state.showLogin = false
                            } else {
                                state.error = model.adGuard.error ?? "Connection or authentication failed"
                            }
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(state.connecting || state.baseURL.isEmpty || state.username.isEmpty || state.password.isEmpty)
                }
            }
            .padding(24)
            .frame(width: 520)
        }
    }

    private func metric(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.title3.bold()).textSelection(.enabled)
        }
    }

    private func listCard(_ title: String, _ values: [String]) -> some View {
        MetricCard(title: title, icon: "chart.bar.xaxis") {
            VStack(alignment: .leading, spacing: 5) {
                if values.isEmpty { Text("No data").foregroundStyle(.secondary) }
                ForEach(Array(values.prefix(8).enumerated()), id: \.offset) { index, value in
                    Text("\(index + 1). \(value)").lineLimit(1).textSelection(.enabled)
                }
            }
        }
    }

    private func displayTime(_ value: String) -> String {
        if value == "—" { return value }
        if let tIndex = value.firstIndex(of: "T") {
            let suffix = value[value.index(after: tIndex)...]
            return String(suffix.prefix(8))
        }
        return value
    }

    private func listenerCard(_ title: String, _ values: [Listener]) -> some View {
        MetricCard(title: title, icon: "server.rack") {
            VStack(alignment: .leading, spacing: 8) {
                if values.isEmpty { Text("Not detected").foregroundStyle(.secondary) }
                ForEach(values) { item in
                    HStack {
                        StatusDot(state: item.isPublic ? .warning : .online)
                        Text("\(item.protocolName) · \(item.address):\(item.port)")
                        Spacer()
                        Text(item.process).foregroundStyle(.secondary)
                    }
                }
            }
        }
    }
}

@MainActor private final class DNSViewState: ObservableObject {
    @Published var showLogin = false
    @Published var baseURL = ""
    @Published var username = ""
    @Published var password = ""
    @Published var error: String?
    @Published var connecting = false
}

struct DiagnosticsView: View {
    @EnvironmentObject var model: AppViewModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    diagnosticButton("SSH Test", .uname)
                    diagnosticButton("Ping Internet", .pingInternet)
                    diagnosticButton("DNS Resolution", .dnsTest)
                    diagnosticButton("WireGuard Status", .wireGuard)
                    diagnosticButton("Detect iperf3", .iperfDetection)
                    Button(model.isRunningDNSPathTest ? "Testing DNS Path…" : "DNS Path Test") {
                        Task { await model.runDNSPathTest() }
                    }
                    .disabled(model.isRunningDNSPathTest)
                }

                GroupBox("Network visibility snapshot") {
                    Grid(alignment: .leading, horizontalSpacing: 20, verticalSpacing: 8) {
                        GridRow { Text("Check").bold(); Text("Expected").bold(); Text("Actual").bold(); Text("Data").bold() }
                        leakRow("Public IPv4", model.system.publicIPv4, model.system.macPublicIP)
                        leakRow("IPv6", "Disabled or explicitly routed", model.system.publicIPv6)
                        leakRow("VPN DNS", model.wireGuard.address.split(separator: "/").first.map(String.init) ?? "Configured resolver", model.listeners.filter { $0.port == 53 }.map(\.address).joined(separator: ", "))
                        leakRow("Default route", "Configured policy", model.system.macLANIP)
                    }
                    .padding(8)
                }

                GroupBox("DNS Path Test") {
                    VStack(alignment: .leading, spacing: 10) {
                        if !model.dnsPath.ran {
                            Text("Run DNS Path Test to compare macOS system resolvers, the local router, AdGuard and a public resolver without changing network settings.")
                                .foregroundStyle(.secondary)
                        } else {
                            HStack {
                                StatusDot(state: model.dnsPath.state)
                                Text(model.dnsPath.summary).fontWeight(.semibold)
                            }
                            dnsRow("System DNS", model.dnsPath.systemResolvers.joined(separator: ", "))
                            dnsRow("Router", model.dnsPath.router)
                            dnsRow("AdGuard", model.dnsPath.adGuard)
                            dnsRow("Test domain", model.dnsPath.testDomain)
                            dnsRow("System answer", answerText(model.dnsPath.systemAnswers))
                            dnsRow("Router answer", answerText(model.dnsPath.routerAnswers))
                            dnsRow("AdGuard answer", answerText(model.dnsPath.adGuardAnswers))
                            dnsRow("Public 1.1.1.1", answerText(model.dnsPath.publicAnswers))

                            HStack(spacing: 18) {
                                Label(model.dnsPath.systemUsesAdGuard ? "Mac uses AdGuard" : "AdGuard not listed in system DNS", systemImage: model.dnsPath.systemUsesAdGuard ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                                    .foregroundStyle(model.dnsPath.systemUsesAdGuard ? .green : .orange)
                                Label(model.dnsPath.adGuardBlocks ? "Ad blocking confirmed" : "Ad blocking failed", systemImage: model.dnsPath.adGuardBlocks ? "checkmark.circle.fill" : "xmark.octagon.fill")
                                    .foregroundStyle(model.dnsPath.adGuardBlocks ? .green : .red)
                                if model.dnsPath.routerBypasses {
                                    Label("Router DNS bypasses AdGuard", systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                                }
                            }
                        }
                    }
                    .padding(8)
                }

                GroupBox("iperf3 — manual only") {
                    HStack {
                        Text("TCP upload/download and UDP tests are intentionally not started automatically.")
                        Spacer()
                        Button("Run iperf3…") {}.disabled(true)
                    }
                    .padding(8)
                }

                if !model.diagnostics.isEmpty {
                    Chart(model.diagnostics.suffix(30)) { item in
                        BarMark(x: .value("Test", item.date), y: .value("Duration", item.milliseconds ?? 0))
                            .foregroundStyle(item.success ? .green : .red)
                    }
                    .frame(height: 220)
                }

                Table(model.diagnostics.reversed()) {
                    TableColumn("Time") { Text($0.date.formatted(date: .abbreviated, time: .standard)) }
                    TableColumn("Test", value: \.name)
                    TableColumn("Result") { Text($0.success ? "Passed" : "Failed").foregroundStyle($0.success ? .green : .red) }
                    TableColumn("Summary", value: \.summary)
                }
                .frame(minHeight: 260)
            }
            .padding(20)
        }
    }

    private func diagnosticButton(_ title: String, _ command: ReadCommand) -> some View {
        Button(title) { Task { await model.runDiagnostic(command, name: title) } }
    }

    private func leakRow(_ name: String, _ expected: String, _ actual: String) -> some View {
        GridRow {
            Text(name)
            Text(expected).foregroundStyle(.secondary)
            Text(actual).textSelection(.enabled)
            Image(systemName: actual.isEmpty || actual == "—" ? "xmark.circle.fill" : "checkmark.circle.fill")
                .foregroundStyle(actual.isEmpty || actual == "—" ? .red : .green)
        }
    }

    private func dnsRow(_ name: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(name).foregroundStyle(.secondary).frame(width: 120, alignment: .leading)
            Text(value.isEmpty ? "—" : value).textSelection(.enabled)
        }
    }

    private func answerText(_ values: [String]) -> String {
        values.isEmpty ? "No answer" : values.joined(separator: ", ")
    }
}

struct RouterView: View {
    @EnvironmentObject var model: AppViewModel
    var reachable: Bool { !model.system.macLANIP.isEmpty && model.system.macLANIP != "—" }
    var body: some View { ScrollView { LazyVGrid(columns: [GridItem(.adaptive(minimum: 340))], spacing: 16) { MetricCard(title: "Home Router", icon: "wifi.router") { VStack(spacing: 10) { HStack { StatusDot(state: reachable ? .online : .offline); Text(reachable ? "LAN detected" : "Not on a LAN"); Spacer() }; KeyValueRow(key: "Current Mac LAN", value: model.system.macLANIP); Text("Open your router admin URL manually. TunnelDeck never stores router credentials or uses private vendor APIs.").foregroundStyle(.secondary) } } }.padding(20) } }
}

struct HomeAccessView: View {
    var body: some View { ContentUnavailableView { Label("Remote Home Access", systemImage: "house.and.flag") } description: { Text("Store imported router WireGuard profiles locally for Macs and phones. Router configuration is never changed automatically.") } actions: { Button("Import Local Profile…") {}.disabled(true) } }
}
