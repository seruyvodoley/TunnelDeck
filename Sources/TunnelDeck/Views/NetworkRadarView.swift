import Foundation
import SwiftUI

struct RadarSocketConnection: Identifiable, Sendable, Hashable {
    var id: String {
        "\(protocolName)|\(state)|\(localHost)|\(localPort)|\(remoteHost)|\(remotePort)|\(process)"
    }

    let protocolName: String
    let state: String
    let localHost: String
    let localPort: String
    let remoteHost: String
    let remotePort: String
    let process: String
    let remoteScope: String
}

struct RadarForwardedFlow: Identifiable, Sendable, Hashable {
    var id: String {
        "\(protocolName)|\(sourceHost)|\(sourcePort)|\(destinationHost)|\(destinationPort)|\(state)"
    }

    let protocolName: String
    let state: String
    let sourceHost: String
    let sourcePort: String
    let destinationHost: String
    let destinationPort: String
    let sourceScope: String
    let destinationScope: String
}

struct RadarBlockedProbe: Identifiable, Sendable, Hashable {
    var id: String { "\(remoteIP)|\(protocolName)|\(destinationPort)" }

    let remoteIP: String
    let protocolName: String
    let destinationPort: String
    var count: Int
}

enum NetworkRadarParser {
    static func sockets(_ text: String) -> [RadarSocketConnection] {
        var result: [RadarSocketConnection] = []

        for raw in text.split(separator: "\n") {
            let fields = raw.split(whereSeparator: \.isWhitespace).map(String.init)
            guard fields.count >= 6 else { continue }

            let proto = fields[0].lowercased()
            guard proto.hasPrefix("tcp") || proto.hasPrefix("udp") else { continue }

            let state = fields[1].uppercased()
            if state == "LISTEN" { continue }

            let local = endpoint(fields[4])
            let remote = endpoint(fields[5])

            if wildcard(remote.host),
               remote.port == "*" || remote.port == "0" || remote.port.isEmpty {
                continue
            }

            // UDP sockets bound to a local port but not connected to a peer
            // are listeners rather than live peer connections.
            if state == "UNCONN" && wildcard(remote.host) {
                continue
            }

            let process = fields.count > 6
                ? fields.dropFirst(6).joined(separator: " ")
                : ""

            result.append(
                RadarSocketConnection(
                    protocolName: proto,
                    state: state,
                    localHost: local.host,
                    localPort: local.port,
                    remoteHost: remote.host,
                    remotePort: remote.port,
                    process: process,
                    remoteScope: scope(remote.host)
                )
            )
        }

        return result.sorted {
            let lhsPublic = $0.remoteScope == "Public"
            let rhsPublic = $1.remoteScope == "Public"
            if lhsPublic != rhsPublic { return lhsPublic && !rhsPublic }
            if $0.protocolName != $1.protocolName {
                return $0.protocolName < $1.protocolName
            }
            return $0.remoteHost < $1.remoteHost
        }
    }

    static func conntrack(_ text: String) -> [RadarForwardedFlow] {
        var result: [RadarForwardedFlow] = []

        for raw in text.split(separator: "\n") {
            let line = String(raw)
            if line == "__TD_CONNTRACK__" { continue }

            let fields = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard let proto = fields.first?.lowercased(),
                  proto == "tcp" || proto == "udp"
            else {
                continue
            }

            var src: String?
            var dst: String?
            var sport: String?
            var dport: String?

            for field in fields {
                if src == nil, field.hasPrefix("src=") {
                    src = String(field.dropFirst(4))
                } else if dst == nil, field.hasPrefix("dst=") {
                    dst = String(field.dropFirst(4))
                } else if sport == nil, field.hasPrefix("sport=") {
                    sport = String(field.dropFirst(6))
                } else if dport == nil, field.hasPrefix("dport=") {
                    dport = String(field.dropFirst(6))
                }

                if src != nil, dst != nil, sport != nil, dport != nil {
                    break
                }
            }

            guard let source = src, let destination = dst else { continue }

            let state: String
            if let explicit = fields.dropFirst(3).first(where: {
                !$0.contains("=") &&
                !$0.hasPrefix("[") &&
                Int($0) == nil
            }) {
                state = explicit.uppercased()
            } else if line.contains("[ASSURED]") {
                state = "ASSURED"
            } else if line.contains("[UNREPLIED]") {
                state = "UNREPLIED"
            } else {
                state = "TRACKED"
            }

            result.append(
                RadarForwardedFlow(
                    protocolName: proto,
                    state: state,
                    sourceHost: source,
                    sourcePort: sport ?? "—",
                    destinationHost: destination,
                    destinationPort: dport ?? "—",
                    sourceScope: scope(source),
                    destinationScope: scope(destination)
                )
            )
        }

        return Array(
            Dictionary(grouping: result, by: \.id)
                .compactMap { $0.value.first }
                .sorted {
                    if $0.sourceHost != $1.sourceHost {
                        return $0.sourceHost < $1.sourceHost
                    }
                    return $0.destinationHost < $1.destinationHost
                }
                .prefix(2_000)
        )
    }

    static func blocked(_ text: String) -> [RadarBlockedProbe] {
        var values: [String: RadarBlockedProbe] = [:]

        for raw in text.split(separator: "\n") {
            let line = String(raw)

            guard let source = token("SRC=", in: line) else { continue }

            let proto = token("PROTO=", in: line) ?? "UNKNOWN"
            let port = token("DPT=", in: line) ?? "—"
            let key = "\(source)|\(proto)|\(port)"

            if var value = values[key] {
                value.count += 1
                values[key] = value
            } else {
                values[key] = RadarBlockedProbe(
                    remoteIP: source,
                    protocolName: proto.uppercased(),
                    destinationPort: port,
                    count: 1
                )
            }
        }

        return values.values.sorted {
            if $0.count != $1.count { return $0.count > $1.count }
            return $0.remoteIP < $1.remoteIP
        }
    }

    static func conntrackAvailable(_ text: String) -> Bool {
        text.contains("__TD_CONNTRACK__")
    }

    private static func token(_ prefix: String, in line: String) -> String? {
        for token in line.split(whereSeparator: \.isWhitespace) {
            let value = String(token)
            if value.hasPrefix(prefix) {
                return String(value.dropFirst(prefix.count))
            }
        }
        return nil
    }

    private static func endpoint(_ raw: String) -> (host: String, port: String) {
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)

        if value.hasPrefix("["),
           let close = value.lastIndex(of: "]") {
            let host = String(value[value.index(after: value.startIndex)..<close])
            let remainder = value[value.index(after: close)...]
            let port = remainder.hasPrefix(":") ? String(remainder.dropFirst()) : ""
            return (host, port)
        }

        guard let separator = value.lastIndex(of: ":") else {
            return (value.trimmingCharacters(in: CharacterSet(charactersIn: "[]")), "")
        }

        let host = String(value[..<separator])
            .trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        let port = String(value[value.index(after: separator)...])

        return (host, port)
    }

    private static func wildcard(_ host: String) -> Bool {
        ["", "*", "0.0.0.0", "::"].contains(host)
    }

    static func scope(_ host: String) -> String {
        let lower = host.lowercased()

        if lower.hasPrefix("10.66.66.") {
            return "VPN"
        }

        if lower == "127.0.0.1" || lower == "::1" {
            return "Loopback"
        }

        if lower.hasPrefix("fe80:") ||
            lower.hasPrefix("fc") ||
            lower.hasPrefix("fd") {
            return "Private"
        }

        let octets = lower.split(separator: ".").compactMap { Int($0) }
        if octets.count == 4 {
            if octets[0] == 10 {
                return "Private"
            }
            if octets[0] == 192 && octets[1] == 168 {
                return "Private"
            }
            if octets[0] == 172 && (16...31).contains(octets[1]) {
                return "Private"
            }
            if octets[0] == 100 && (64...127).contains(octets[1]) {
                return "Carrier NAT"
            }
            return "Public"
        }

        if lower.contains(":") && !wildcard(lower) {
            return "Public"
        }

        return "Unknown"
    }
}

@MainActor
final class NetworkRadarController: ObservableObject {
    @Published private(set) var sockets: [RadarSocketConnection] = []
    @Published private(set) var flows: [RadarForwardedFlow] = []
    @Published private(set) var blocked: [RadarBlockedProbe] = []
    @Published private(set) var conntrackAvailable = false
    @Published private(set) var isRefreshing = false
    @Published private(set) var lastUpdated: Date?
    @Published private(set) var message: String?

    func refresh(using model: AppViewModel) async {
        guard !isRefreshing else { return }

        isRefreshing = true
        defer { isRefreshing = false }

        let configuration = model.configuration

        let socketResult = try? await model.ssh.execute(
            .activeConnections,
            configuration: configuration
        )

        let conntrackResult = try? await model.ssh.execute(
            .conntrackFlows,
            configuration: configuration
        )

        let blockedResult = try? await model.ssh.execute(
            .blockedProbes,
            configuration: configuration
        )

        if let socketResult, socketResult.succeeded {
            sockets = NetworkRadarParser.sockets(socketResult.stdout)
        } else {
            sockets = []
        }

        if let conntrackResult, conntrackResult.succeeded {
            conntrackAvailable = NetworkRadarParser.conntrackAvailable(conntrackResult.stdout)
            flows = NetworkRadarParser.conntrack(conntrackResult.stdout)
        } else {
            conntrackAvailable = false
            flows = []
        }

        if let blockedResult, blockedResult.succeeded {
            blocked = NetworkRadarParser.blocked(blockedResult.stdout)
        } else {
            blocked = []
        }

        if socketResult?.succeeded != true {
            message = "Server connection telemetry is unavailable over SSH."
        } else if !conntrackAvailable {
            message = "Server sockets are visible. Forwarded/NAT visibility needs conntrack-tools or /proc/net/nf_conntrack on the VPS."
        } else {
            message = nil
        }

        lastUpdated = Date()
    }
}

private enum NetworkRadarSection: String, CaseIterable, Identifiable {
    case sockets = "Server sockets"
    case forwarded = "Forwarded / NAT"
    case blocked = "Blocked probes"
    case wireGuard = "WireGuard peers"

    var id: String { rawValue }
}

struct NetworkRadarView: View {
    @EnvironmentObject var model: AppViewModel
    @StateObject private var radar = NetworkRadarController()
    @State private var section: NetworkRadarSection = .sockets

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 12) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Network Radar").font(.title2.bold())
                        Text("Live visibility from server sockets, conntrack, kernel firewall logs and WireGuard.")
                            .foregroundStyle(.secondary)
                    }

                    Spacer()

                    if let updated = radar.lastUpdated {
                        Text("Updated \(updated.formatted(date: .omitted, time: .standard))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    Button {
                        Task { await radar.refresh(using: model) }
                    } label: {
                        Label(
                            radar.isRefreshing ? "Refreshing…" : "Refresh",
                            systemImage: "arrow.clockwise"
                        )
                    }
                    .disabled(radar.isRefreshing)
                }

                LazyVGrid(
                    columns: [GridItem(.adaptive(minimum: 180), spacing: 10)],
                    spacing: 10
                ) {
                    radarMetric(
                        "Server sockets",
                        String(radar.sockets.count),
                        "point.3.connected.trianglepath.dotted"
                    )

                    radarMetric(
                        "Public peers",
                        String(radar.sockets.filter { $0.remoteScope == "Public" }.count),
                        "globe"
                    )

                    radarMetric(
                        "Forwarded flows",
                        radar.conntrackAvailable ? String(radar.flows.count) : "Unavailable",
                        "arrow.triangle.branch"
                    )

                    radarMetric(
                        "Blocked · 30 min",
                        String(radar.blocked.reduce(0) { $0 + $1.count }),
                        "hand.raised.fill"
                    )

                    radarMetric(
                        "WG online",
                        String(model.wireGuard.peers.filter { $0.status == .online }.count),
                        "lock.shield.fill"
                    )
                }

                if let message = radar.message {
                    Label(message, systemImage: "info.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }

                Picker("View", selection: $section) {
                    ForEach(NetworkRadarSection.allCases) {
                        Text($0.rawValue).tag($0)
                    }
                }
                .pickerStyle(.segmented)
            }
            .padding()

            Divider()

            switch section {
            case .sockets:
                socketTable
            case .forwarded:
                flowTable
            case .blocked:
                blockedTable
            case .wireGuard:
                wireGuardTable
            }
        }
        .task {
            while !Task.isCancelled {
                await radar.refresh(using: model)
                try? await Task.sleep(for: .seconds(10))
            }
        }
    }

    private var socketTable: some View {
        Group {
            if radar.sockets.isEmpty {
                ContentUnavailableView(
                    "No active server sockets",
                    systemImage: "network.slash",
                    description: Text("No connected TCP/UDP peers were reported by ss.")
                )
            } else {
                Table(radar.sockets) {
                    TableColumn("Protocol") {
                        Text($0.protocolName.uppercased())
                    }
                    .width(min: 65, ideal: 75)

                    TableColumn("State", value: \.state)
                        .width(min: 80, ideal: 100)

                    TableColumn("Local") {
                        Text("\($0.localHost):\($0.localPort)")
                            .textSelection(.enabled)
                    }

                    TableColumn("Remote") {
                        Text("\($0.remoteHost):\($0.remotePort)")
                            .textSelection(.enabled)
                    }

                    TableColumn("Scope", value: \.remoteScope)
                        .width(min: 75, ideal: 90)

                    TableColumn("Process") {
                        Text($0.process.isEmpty ? "—" : $0.process)
                            .lineLimit(1)
                    }
                }
            }
        }
    }

    private var flowTable: some View {
        Group {
            if !radar.conntrackAvailable {
                ContentUnavailableView(
                    "Conntrack unavailable",
                    systemImage: "arrow.triangle.branch",
                    description: Text("Install conntrack-tools on the VPS to see forwarded and NAT flows.")
                )
            } else if radar.flows.isEmpty {
                ContentUnavailableView(
                    "No forwarded flows",
                    systemImage: "arrow.left.arrow.right",
                    description: Text("Conntrack is available but currently contains no parsed TCP/UDP flows.")
                )
            } else {
                Table(radar.flows) {
                    TableColumn("Protocol") {
                        Text($0.protocolName.uppercased())
                    }
                    .width(min: 65, ideal: 75)

                    TableColumn("State", value: \.state)
                        .width(min: 80, ideal: 100)

                    TableColumn("Source") {
                        Text("\($0.sourceHost):\($0.sourcePort)")
                            .textSelection(.enabled)
                    }

                    TableColumn("Source scope", value: \.sourceScope)
                        .width(min: 80, ideal: 95)

                    TableColumn("Destination") {
                        Text("\($0.destinationHost):\($0.destinationPort)")
                            .textSelection(.enabled)
                    }

                    TableColumn("Destination scope", value: \.destinationScope)
                        .width(min: 90, ideal: 105)
                }
            }
        }
    }

    private var blockedTable: some View {
        Group {
            if radar.blocked.isEmpty {
                ContentUnavailableView(
                    "No logged blocked probes",
                    systemImage: "checkmark.shield",
                    description: Text("This does not prove that nobody scanned the VPS. The firewall must log dropped packets for source IPs to appear here.")
                )
            } else {
                Table(radar.blocked) {
                    TableColumn("Remote IP", value: \.remoteIP)

                    TableColumn("Protocol", value: \.protocolName)
                        .width(min: 70, ideal: 85)

                    TableColumn("Target port", value: \.destinationPort)
                        .width(min: 75, ideal: 90)

                    TableColumn("Hits") {
                        Text(String($0.count))
                            .monospacedDigit()
                    }
                    .width(min: 60, ideal: 70)
                }
            }
        }
    }

    private var wireGuardTable: some View {
        Group {
            if model.wireGuard.peers.isEmpty {
                ContentUnavailableView(
                    "No WireGuard peers",
                    systemImage: "lock.slash",
                    description: Text("wg0 did not report any configured peers.")
                )
            } else {
                Table(model.wireGuard.peers) {
                    TableColumn("Name", value: \.name)

                    TableColumn("VPN IP", value: \.vpnIP)

                    TableColumn("Endpoint", value: \.endpoint)

                    TableColumn("Handshake") {
                        Text(
                            $0.latestHandshake?.formatted(
                                .relative(presentation: .numeric)
                            ) ?? "Never"
                        )
                    }

                    TableColumn("RX") {
                        Text($0.receivedBytes.byteString)
                    }

                    TableColumn("TX") {
                        Text($0.sentBytes.byteString)
                    }

                    TableColumn("Status") { peer in
                        HStack {
                            StatusDot(state: peer.status)
                            Text(peer.status.rawValue.capitalized)
                        }
                    }
                }
            }
        }
    }

    private func radarMetric(
        _ title: String,
        _ value: String,
        _ icon: String
    ) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Text(value)
                    .font(.title3.bold())
                    .monospacedDigit()
                    .lineLimit(1)
            }

            Spacer()
        }
        .padding(10)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10))
    }
}
