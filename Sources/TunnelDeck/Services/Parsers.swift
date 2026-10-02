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


enum SecurityAuditParser {
    static func parseSSHConfig(_ text: String, configuredPort: Int, authLog: String) -> SSHSecuritySnapshot {
        let values = Dictionary(uniqueKeysWithValues: text.split(separator: "\n").compactMap { raw -> (String, String)? in
            let parts = raw.split(whereSeparator: \.isWhitespace)
            guard parts.count >= 2 else { return nil }
            return (String(parts[0]).lowercased(), String(parts[1]))
        })

        var snapshot = SSHSecuritySnapshot()
        snapshot.available = !values.isEmpty
        snapshot.port = values["port"] ?? "—"
        snapshot.passwordAuthentication = values["passwordauthentication"] ?? "—"
        snapshot.keyboardInteractiveAuthentication = values["kbdinteractiveauthentication"] ?? "—"
        snapshot.pubkeyAuthentication = values["pubkeyauthentication"] ?? "—"
        snapshot.permitRootLogin = values["permitrootlogin"] ?? "—"
        snapshot.permitEmptyPasswords = values["permitemptypasswords"] ?? "—"
        snapshot.maxAuthTries = values["maxauthtries"] ?? "—"
        snapshot.maxSessions = values["maxsessions"] ?? "—"
        snapshot.x11Forwarding = values["x11forwarding"] ?? "—"
        snapshot.allowTCPForwarding = values["allowtcpforwarding"] ?? "—"

        let lines = authLog.split(separator: "\n").map(String.init)
        snapshot.failedLogins24h = lines.filter { line in
            let lower = line.lowercased()
            return lower.contains("failed password") || lower.contains("invalid user") || lower.contains("authentication failure")
        }.count
        let accepted = lines.filter { $0.lowercased().contains("accepted ") }
        snapshot.successfulLogins24h = accepted.count
        snapshot.lastSuccessfulLogin = accepted.last ?? "—"

        var findings: [String] = []
        var state: HealthState = snapshot.available ? .online : .warning

        func rank(_ value: HealthState) -> Int {
            switch value {
            case .unknown: return 0
            case .online: return 1
            case .warning: return 2
            case .critical: return 3
            case .offline: return 4
            }
        }

        func escalate(_ next: HealthState) {
            if rank(next) > rank(state) { state = next }
        }

        if !snapshot.available {
            findings.append("Effective sshd configuration could not be read.")
        }
        if snapshot.pubkeyAuthentication == "no" {
            findings.append("Public-key authentication is disabled.")
            escalate(.critical)
        }
        if snapshot.permitEmptyPasswords == "yes" {
            findings.append("Empty-password authentication is permitted.")
            escalate(.critical)
        }
        if snapshot.passwordAuthentication == "yes" {
            findings.append("Password authentication is enabled.")
            escalate(.warning)
        }
        if snapshot.keyboardInteractiveAuthentication == "yes" {
            findings.append("Keyboard-interactive authentication is enabled.")
            escalate(.warning)
        }
        if snapshot.permitRootLogin == "yes" && snapshot.passwordAuthentication == "yes" {
            findings.append("Root password login is effectively allowed.")
            escalate(.critical)
        } else if snapshot.permitRootLogin == "yes" {
            findings.append("Direct root login is allowed.")
            escalate(.warning)
        }
        if let port = Int(snapshot.port), port != configuredPort {
            findings.append("sshd reports port \(port), while TunnelDeck is configured for \(configuredPort).")
            escalate(.warning)
        }
        if let tries = Int(snapshot.maxAuthTries), tries > 6 {
            findings.append("MaxAuthTries is high (\(tries)).")
            escalate(.warning)
        }

        snapshot.findings = findings
        snapshot.state = state
        return snapshot
    }

    static func wireGuardPorts(_ text: String) -> [Int: String] {
        var result: [Int: String] = [:]
        var currentInterface: String?
        for raw in text.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("interface:") {
                currentInterface = line.split(separator: ":", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("listening port:"),
                      let interface = currentInterface,
                      let value = line.split(separator: ":", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces),
                      let port = Int(value) {
                result[port] = interface
            }
        }
        return result
    }

    static func openVPNPorts(_ text: String) -> [Int: String] {
        var result: [Int: String] = [:]
        var currentName: String?
        for raw in text.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("["), line.hasSuffix("]") {
                let path = String(line.dropFirst().dropLast())
                currentName = URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent
            } else if line.hasPrefix("port "),
                      let name = currentName,
                      let port = Int(line.split(whereSeparator: \.isWhitespace).last ?? "") {
                result[port] = name
            }
        }
        return result
    }

    static func classifyListeners(
        _ listeners: [Listener],
        host: String,
        cleanWireGuardPort: Int?,
        wireGuardAll: String,
        openVPNBinds: String
    ) -> (publicItems: [SecurityListener], privateItems: [SecurityListener]) {
        let wgPorts = wireGuardPorts(wireGuardAll)
        let ovpnPorts = openVPNPorts(openVPNBinds)

        let grouped = Dictionary(grouping: listeners) { listener in
            "\(listener.protocolName.lowercased())|\(listener.port)"
        }

        var publicRows: [SecurityListener] = []
        var privateRows: [SecurityListener] = []

        for group in grouped.values {
            guard let sample = group.first else { continue }
            let addresses = Array(Set(group.map(\.address))).sorted()
            let process = group.map(\.process).first(where: { !$0.isEmpty }) ?? ""
            let isPublic = group.contains { $0.isPublic || (!host.isEmpty && $0.address == host) }

            let service: String
            let note: String
            let state: HealthState

            if sample.port == cleanWireGuardPort || wgPorts[sample.port] == "wg0" {
                service = "Clean WireGuard"
                note = "Expected VPN listener"
                state = .online
            } else if let interface = wgPorts[sample.port] {
                if interface.localizedCaseInsensitiveContains("antizapret") {
                    service = "AntiZapret WireGuard"
                } else if interface == "vpn" {
                    service = "Full VPN WireGuard"
                } else {
                    service = "WireGuard (\(interface))"
                }
                note = "Expected VPN listener"
                state = .online
            } else if let profile = ovpnPorts[sample.port] {
                if profile.localizedCaseInsensitiveContains("antizapret") {
                    service = "AntiZapret OpenVPN"
                } else if profile == "vpn-udp" || profile == "vpn" {
                    service = "Full VPN OpenVPN"
                } else {
                    service = "OpenVPN (\(profile))"
                }
                note = "Expected VPN listener"
                state = .online
            } else if process.localizedCaseInsensitiveContains("openvpn") {
                service = "OpenVPN"
                note = "Detected OpenVPN listener"
                state = .online
            } else if process.localizedCaseInsensitiveContains("sshd") || sample.port == 22 {
                service = "SSH"
                note = "Remote administration"
                state = .online
            } else if process.localizedCaseInsensitiveContains("AdGuardHome") && sample.port == 53 {
                service = "AdGuard DNS"
                note = isPublic ? "DNS must not be public" : "VPN/private DNS"
                state = isPublic ? .critical : .online
            } else if process.localizedCaseInsensitiveContains("AdGuardHome") {
                service = "AdGuard Web"
                note = isPublic ? "Admin UI must not be public" : "VPN/private web UI"
                state = isPublic ? .critical : .online
            } else {
                service = process.isEmpty ? "Unknown listener" : process
                note = isPublic ? "Review this public listener" : "Private/local listener"
                state = isPublic ? .warning : .online
            }

            let row = SecurityListener(
                service: service,
                protocolName: sample.protocolName.lowercased(),
                port: sample.port,
                addresses: addresses,
                process: process,
                state: state,
                note: note
            )
            if isPublic {
                publicRows.append(row)
            } else if addresses.contains(where: { $0.hasPrefix("10.") || $0.hasPrefix("172.") || $0.hasPrefix("192.168.") }) &&
                        (service.hasPrefix("AdGuard") || service.contains("WireGuard")) {
                privateRows.append(row)
            }
        }

        let sort: (SecurityListener, SecurityListener) -> Bool = { lhs, rhs in
            lhs.port == rhs.port ? lhs.service < rhs.service : lhs.port < rhs.port
        }
        return (publicRows.sorted(by: sort), privateRows.sorted(by: sort))
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