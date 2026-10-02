import Foundation

enum SSHOutputParser {
    static func lines(_ result: CommandResult) -> [String] {
        result.stdout.replacingOccurrences(of: "\r\n", with: "\n").split(separator: "\n").map(String.init)
    }
}

enum SystemctlParser {
    static func parse(_ text: String) -> [UnitStatus] {
        var values: [String: String] = [:]
        var result: [UnitStatus] = []
        func flush() {
            if let id = values["Id"] { result.append(UnitStatus(name: id, activeState: values["ActiveState"] ?? "unknown", subState: values["SubState"] ?? "unknown")) }
            values.removeAll()
        }
        for line in text.components(separatedBy: .newlines) {
            if line.isEmpty { flush(); continue }
            let pair = line.split(separator: "=", maxSplits: 1).map(String.init)
            if pair.count == 2 { values[pair[0]] = pair[1] }
        }
        flush()
        return result
    }
}

enum SSParser {
    static func parse(_ text: String) -> [Listener] {
        text.split(separator: "\n").compactMap { raw in
            let fields = raw.split(whereSeparator: \.isWhitespace)
            guard fields.count >= 5 else { return nil }
            let proto = String(fields[0])
            let local = String(fields[4])
            guard let separator = local.lastIndex(of: ":"), let port = Int(local[local.index(after: separator)...]) else { return nil }
            var address = String(local[..<separator])
            address = address.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            let process = fields.count > 6 ? fields[6...].joined(separator: " ") : ""
            return Listener(protocolName: proto, address: address, port: port, process: process)
        }
    }
}

enum WireGuardParser {
    static func parse(_ text: String, now: Date = Date(), timeout: TimeInterval = 180) -> WireGuardSnapshot {
        var snapshot = WireGuardSnapshot()
        var peer: WireGuardPeer?
        func finishPeer() { if let peer { snapshot.peers.append(peer) } }
        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("interface:") { snapshot.interface = value(line); snapshot.state = .online }
            else if line.hasPrefix("public key:") && peer == nil { snapshot.publicKey = short(value(line)) }
            else if line.hasPrefix("listening port:") { snapshot.listenPort = value(line) }
            else if line.hasPrefix("peer:") {
                finishPeer()
                let key = value(line)
                peer = WireGuardPeer(id: key, name: "Peer \(snapshot.peers.count + 1)", vpnIP: "—", publicKey: short(key), endpoint: "—", latestHandshake: nil, receivedBytes: 0, sentBytes: 0, status: .offline)
            } else if line.hasPrefix("endpoint:") { peer?.endpoint = value(line) }
            else if line.hasPrefix("allowed ips:") { peer?.vpnIP = value(line).split(separator: ",").first.map(String.init) ?? "—" }
            else if line.hasPrefix("latest handshake:") {
                let age = parseAge(value(line)); let date = age.map { now.addingTimeInterval(-$0) }
                peer?.latestHandshake = date; peer?.status = (age ?? .infinity) <= timeout ? .online : .offline
            } else if line.hasPrefix("transfer:") {
                let parts = line.replacingOccurrences(of: "transfer:", with: "").split(separator: ",")
                if parts.count == 2 { peer?.receivedBytes = parseBytes(String(parts[0])); peer?.sentBytes = parseBytes(String(parts[1])) }
            }
        }
        finishPeer()
        snapshot.receivedBytes = snapshot.peers.reduce(0) { $0 + $1.receivedBytes }
        snapshot.sentBytes = snapshot.peers.reduce(0) { $0 + $1.sentBytes }
        return snapshot
    }

    private static func value(_ line: String) -> String { line.split(separator: ":", maxSplits: 1).dropFirst().first.map { $0.trimmingCharacters(in: .whitespaces) } ?? "" }
    private static func short(_ value: String) -> String { value.count > 14 ? "\(value.prefix(7))…\(value.suffix(7))" : value }
    private static func parseBytes(_ value: String) -> UInt64 {
        let parts = value.trimmingCharacters(in: .whitespaces).split(separator: " ")
        guard let amount = Double(parts.first ?? "0") else { return 0 }
        let multiplier: Double = value.contains("GiB") ? 1_073_741_824 : value.contains("MiB") ? 1_048_576 : value.contains("KiB") ? 1024 : 1
        return UInt64(amount * multiplier)
    }
    private static func parseAge(_ value: String) -> TimeInterval? {
        if value == "never" { return nil }
        let regex = try? NSRegularExpression(pattern: #"(\d+)\s+(second|minute|hour|day)s?"#)
        let ns = value as NSString
        return regex?.matches(in: value, range: NSRange(location: 0, length: ns.length)).reduce(0) { total, match in
            let number = Double(ns.substring(with: match.range(at: 1))) ?? 0
            let unit = ns.substring(with: match.range(at: 2))
            return total + number * (unit == "day" ? 86400 : unit == "hour" ? 3600 : unit == "minute" ? 60 : 1)
        }
    }
}

enum ProfileParser {
    static func parseListing(_ text: String) -> [ProfileMetadata] {
        text.split(separator: "\n").compactMap { line in
            let fields = line.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            guard let path = fields.first, path.hasSuffix(".conf") || path.hasSuffix(".ovpn") else { return nil }
            let name = URL(fileURLWithPath: path).lastPathComponent
            let type = path.hasSuffix(".ovpn") ? "OpenVPN" : "WireGuard"
            let lower = path.lowercased()
            let category = lower.contains("antizapret") ? (lower.contains("vpn") && !lower.contains("client") ? "Full VPN AntiZapret" : "AntiZapret") : "Clean FULL-WG"
            return ProfileMetadata(name: name, type: type, endpoint: "Not downloaded", port: "—", dns: "Hidden", allowedIPs: "Hidden", mtu: "—", modified: fields.count > 2 ? fields[2] : "—", path: path, category: category)
        }
    }
}
