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
    static func report(results: [ReadCommand: CommandResult], listeners: [Listener], system: SystemSnapshot, wireGuard: WireGuardSnapshot, host: String) -> HealthReport {
        var issues: [HealthIssue] = []
        func add(_ id: String, _ title: String, _ explanation: String, _ details: String, _ state: HealthState, _ fix: String? = nil) {
            issues.append(HealthIssue(id: id, title: title, explanation: explanation, technicalDetails: SecretRedactor.redact(details), state: state, fix: fix))
        }
        if results[.hostname]?.succeeded != true { add("ssh", "VPS is unreachable", "SSH authentication or network connectivity failed.", results[.hostname]?.stderr ?? "No response", .offline) }
        if results[.wireGuardService]?.stdout.trimmingCharacters(in: .whitespacesAndNewlines) != "active" { add("wg", "WireGuard is not active", "wg-quick@wg0 must be active for VPN clients.", results[.wireGuardService]?.stdout ?? "", .offline, "restart-wg0") }
        if wireGuard.address == "—" || wireGuard.address.isEmpty { add("wg-address", "WireGuard address missing", "The wg0 interface has no IPv4 address.", wireGuard.address, .offline) }
        let udp = results[.udpListeners]?.stdout ?? ""
        if wireGuard.listenPort != "—" && !udp.contains(":\(wireGuard.listenPort)") { add("wg-port", "WireGuard UDP port is not listening", "The configured WireGuard port was not found in UDP listeners.", wireGuard.listenPort, .offline) }
        if results[.ipForward]?.stdout.trimmingCharacters(in: .whitespacesAndNewlines) != "1" { add("forward", "IPv4 forwarding is disabled", "VPN traffic cannot be routed through the VPS.", results[.ipForward]?.stdout ?? "", .offline) }
        if !(results[.natRules]?.stdout.contains("MASQUERADE") ?? false) { add("nat", "NAT masquerade rule missing", "Full-tunnel clients may not reach the internet.", results[.natRules]?.stdout ?? "", .warning) }
        if results[.pingInternet]?.succeeded != true { add("internet", "Server internet test failed", "The VPS could not reach the public internet.", results[.pingInternet]?.stderr ?? "", .offline) }
        if results[.dnsTest]?.succeeded != true { add("dns", "Server DNS resolution failed", "The system resolver could not resolve a test domain.", results[.dnsTest]?.stderr ?? "", .warning) }
        if results[.adGuardStatus]?.stdout.trimmingCharacters(in: .whitespacesAndNewlines) != "active" { add("adguard", "AdGuard Home is inactive", "Clients configured to use AdGuard DNS may lose resolution.", results[.adGuardStatus]?.stdout ?? "", .warning, "restart-adguard") }
        if results[.antiZapretStatus]?.stdout.trimmingCharacters(in: .whitespacesAndNewlines) != "active" { add("antizapret", "AntiZapret is inactive", "AntiZapret routing and DNS may be unavailable.", results[.antiZapretStatus]?.stdout ?? "", .warning, "restart-antizapret") }
        let exposed = listeners.filter { $0.isPublic || (!host.isEmpty && $0.address == host) }
        for listener in exposed where [53, 3000].contains(listener.port) { add("public-\(listener.id)", "Sensitive service is publicly exposed", "DNS or a management UI is bound to a public/wildcard address.", "\(listener.protocolName) \(listener.address):\(listener.port) \(listener.process)", .offline) }
        let expectedPorts = Set([22, Int(wireGuard.listenPort) ?? 51820])
        for listener in exposed where !expectedPorts.contains(listener.port) && ![53, 3000].contains(listener.port) { add("unexpected-\(listener.id)", "Unexpected public listener", "A port outside the configured firewall baseline is listening publicly.", "\(listener.protocolName) \(listener.address):\(listener.port) \(listener.process)", .warning) }
        if system.diskPercent >= 90 { add("disk", "Disk usage is above 90%", "Backups and services may fail when storage is exhausted.", "\(system.diskPercent)%", .offline) }
        else if system.diskPercent >= 80 { add("disk", "Disk usage is elevated", "Plan cleanup before storage becomes critical.", "\(system.diskPercent)%", .warning) }
        if system.memoryPercent >= 90 { add("ram", "Memory usage is above 90%", "Services may be killed under memory pressure.", "\(system.memoryPercent)%", .warning) }
        if wireGuard.peers.contains(where: { $0.latestHandshake == nil }) { add("peers", "Some peers have no handshake", "One or more configured peers have never completed a handshake.", "Check the WireGuard peer table.", .warning) }
        let state: HealthState = issues.contains { $0.state == .offline } ? .offline : (issues.isEmpty ? .online : .warning)
        return HealthReport(date: Date(), state: state, issues: issues)
    }
}

enum NotificationService {
    static func request() { UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in } }
    static func send(title: String, body: String, id: String) {
        let content = UNMutableNotificationContent(); content.title = title; content.body = body
        UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: id, content: content, trigger: nil))
    }
}
