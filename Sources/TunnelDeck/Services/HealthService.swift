import Foundation
import UserNotifications

actor ActivityStore {
    private let url: URL
    init() {
        let folder = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("TunnelDeck", isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        url = folder.appendingPathComponent("activity.json")
    }
    func load() -> [ActivityRecord] { (try? Data(contentsOf: url)).flatMap { try? JSONDecoder().decode([ActivityRecord].self, from: $0) } ?? [] }
    func append(operation: String, server: String, preview: String, result: String, rollback: String? = nil) {
        var records = load()
        records.append(ActivityRecord(id: UUID(), timestamp: Date(), operation: operation, server: server, preview: SecretRedactor.redact(preview), result: SecretRedactor.redact(result), rollback: rollback.map(SecretRedactor.redact)))
        if let data = try? JSONEncoder().encode(Array(records.suffix(1_000))) { try? data.write(to: url, options: .atomic) }
    }
}

enum HealthEvaluator {
    static func report(results: [ReadCommand: CommandResult], listeners: [Listener], system: SystemSnapshot, wireGuard: WireGuardSnapshot, host: String, approvedListenerIDs: Set<String> = [], ignoredPeerIDs: Set<String> = []) -> HealthReport {
        var issues: [HealthIssue] = []
        func add(_ id: String, _ title: String, _ explanation: String, _ details: String, _ state: HealthState, _ fix: String? = nil) {
            issues.append(HealthIssue(id: id, title: title, explanation: explanation, technicalDetails: SecretRedactor.redact(details), state: state, fix: fix))
        }

        if results[.hostname]?.succeeded != true {
            add("ssh", "VPS is unreachable", "SSH authentication or network connectivity failed.", results[.hostname]?.stderr ?? "No response", .offline)
        }
        if results[.wireGuardService]?.stdout.trimmingCharacters(in: .whitespacesAndNewlines) != "active" {
            add("wg", "WireGuard is not active", "wg-quick@wg0 must be active for VPN clients.", results[.wireGuardService]?.stdout ?? "", .critical, "restart-wg0")
        }
        if wireGuard.address == "—" || wireGuard.address.isEmpty {
            add("wg-address", "WireGuard address missing", "The wg0 interface has no IPv4 address.", wireGuard.address, .critical)
        }
        let udp = results[.udpListeners]?.stdout ?? ""
        if wireGuard.listenPort != "—" && !wireGuard.listenPort.isEmpty && !udp.contains(":\(wireGuard.listenPort)") {
            add("wg-port", "WireGuard UDP port is not listening", "The configured WireGuard port was not found in UDP listeners.", wireGuard.listenPort, .critical)
        }
        if results[.ipForward]?.stdout.trimmingCharacters(in: .whitespacesAndNewlines) != "1" {
            add("forward", "IPv4 forwarding is disabled", "VPN traffic cannot be routed through the VPS.", results[.ipForward]?.stdout ?? "", .critical)
        }
        if !(results[.natRules]?.stdout.contains("MASQUERADE") ?? false) {
            add("nat", "NAT masquerade rule missing", "Full-tunnel clients may not reach the internet.", results[.natRules]?.stdout ?? "", .warning)
        }
        if results[.pingInternet]?.succeeded != true {
            add("internet", "Server internet test failed", "The VPS could not reach the public internet.", results[.pingInternet]?.stderr ?? "", .critical)
        }
        if results[.dnsTest]?.succeeded != true {
            add("dns", "Server DNS resolution failed", "The system resolver could not resolve a test domain.", results[.dnsTest]?.stderr ?? "", .warning)
        }
        if results[.adGuardStatus]?.stdout.trimmingCharacters(in: .whitespacesAndNewlines) != "active" {
            add("adguard", "AdGuard Home is inactive", "Clients configured to use AdGuard DNS may lose resolution.", results[.adGuardStatus]?.stdout ?? "", .warning, "restart-adguard")
        }
        if results[.antiZapretStatus]?.stdout.trimmingCharacters(in: .whitespacesAndNewlines) != "active" {
            add("antizapret", "AntiZapret is inactive", "AntiZapret routing and DNS may be unavailable.", results[.antiZapretStatus]?.stdout ?? "", .warning, "restart-antizapret")
        }

        let exposed = listeners.filter { $0.isPublic || (!host.isEmpty && $0.address == host) }
        for listener in exposed where listener.port == 53 {
            add("public-dns-\(listener.id)", "DNS is publicly exposed", "A DNS listener is bound to a public or wildcard address.", "\(listener.protocolName) \(listener.address):\(listener.port) \(listener.process)", .critical)
        }
        for listener in exposed where listener.port != 53 && listener.process.localizedCaseInsensitiveContains("AdGuardHome") {
            add("public-adguard-web-\(listener.id)", "AdGuard web UI is publicly exposed", "The AdGuard Home management interface is reachable on a public or wildcard address.", "\(listener.protocolName) \(listener.address):\(listener.port) \(listener.process)", .critical)
        }

        var expectedPorts = Set([22, Int(wireGuard.listenPort) ?? 51820])
        expectedPorts.formUnion(wireGuardListenPorts(results[.wireGuardAll]?.stdout ?? ""))

        let activeOpenVPN = SystemctlParser.parse(results[.units]?.stdout ?? "").contains {
            $0.name.localizedCaseInsensitiveContains("openvpn-server@") && $0.activeState == "active"
        }

        var seenUnexpected = Set<String>()
        for listener in exposed {
            let isKnownWireGuard = expectedPorts.contains(listener.port)
            let isKnownOpenVPN = activeOpenVPN && listener.process.localizedCaseInsensitiveContains("openvpn")
            let isAdGuard = listener.process.localizedCaseInsensitiveContains("AdGuardHome")
            guard !isKnownWireGuard,
                  !isKnownOpenVPN,
                  listener.port != 53,
                  !isAdGuard,
                  !approvedListenerIDs.contains(listener.id) else { continue }

            let canonical = "\(listener.protocolName.lowercased())-\(listener.port)-\(listener.process.lowercased())"
            guard seenUnexpected.insert(canonical).inserted else { continue }
            add("unexpected-\(listener.id)", "New public listener detected", "This listener is outside the confirmed baseline for this VPS.", "\(listener.protocolName) \(listener.address):\(listener.port) \(listener.process)", .warning, "approve-listener")
        }

        if system.diskPercent >= 90 {
            add("disk", "Disk usage is above 90%", "Backups and services may fail when storage is exhausted.", "\(system.diskPercent)%", .critical)
        } else if system.diskPercent >= 80 {
            add("disk", "Disk usage is elevated", "Plan cleanup before storage becomes critical.", "\(system.diskPercent)%", .warning)
        }
        if system.memoryPercent >= 90 {
            add("ram", "Memory usage is above 90%", "Services may be killed under memory pressure.", "\(system.memoryPercent)%", .warning)
        }
        for peer in wireGuard.peers where peer.latestHandshake == nil && !ignoredPeerIDs.contains(peer.id) {
            let label = peer.vpnIP == "—" ? peer.name : peer.vpnIP
            add(
                "peer-never-\(peer.id)",
                "Peer \(label) has never connected",
                "This configured WireGuard peer has never completed a handshake.",
                "Allowed IP: \(peer.vpnIP)\nPublic key: \(peer.publicKey)",
                .warning,
                "ignore-peer"
            )
        }

        let state: HealthState
        if issues.contains(where: { $0.state == .offline }) {
            state = .offline
        } else if issues.contains(where: { $0.state == .critical }) {
            state = .critical
        } else if issues.isEmpty {
            state = .online
        } else {
            state = .warning
        }
        return HealthReport(date: Date(), state: state, issues: issues)
    }

    private static func wireGuardListenPorts(_ output: String) -> Set<Int> {
        Set(output.split(separator: "\n").compactMap { rawLine in
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("listening port:") else { return nil }
            return Int(line.split(separator: ":", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces) ?? "")
        })
    }
}

enum NotificationService {
    static func request() { UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in } }
    static func send(title: String, body: String, id: String) {
        let content = UNMutableNotificationContent(); content.title = title; content.body = body
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: id, content: content, trigger: nil))
    }
}