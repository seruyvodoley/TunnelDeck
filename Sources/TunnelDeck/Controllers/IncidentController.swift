import Foundation

enum IncidentEngine {
    static func incidents(events: [MonitoringEvent], nodeID: UUID) -> [Incident] {
        var result: [Incident] = []; var active: [String: Int] = [:]; var nodeOutage: Int?
        for event in events.sorted(by: { $0.timestamp < $1.timestamp }) {
            if event.component == "vps" {
                if event.recovered { if let index = nodeOutage { close(&result[index], event); active.removeValue(forKey: "vps"); nodeOutage = nil } }
                else if nodeOutage == nil { result.append(make(nodeID, event, "VPS connectivity outage", ["VPS", "SSH", "wg0", "AdGuard", "AntiZapret"])); nodeOutage = result.indices.last; active["vps"] = nodeOutage }
                continue
            }
            if nodeOutage != nil, ["wg0", "adguard", "antizapret"].contains(event.component) { continue }
            if event.recovered { if let index = active[event.component] { close(&result[index], event); active.removeValue(forKey: event.component) } }
            else if active[event.component] == nil, event.state != .online { result.append(make(nodeID, event, event.title, [name(event.component)])); active[event.component] = result.indices.last }
            else if let index = active[event.component] { result[index].timeline.append(IncidentTimelineEntry(id: UUID(), timestamp: event.timestamp, state: event.state, message: event.title)) }
        }
        return result
    }
    static func metrics(_ incidents: [Incident], now: Date = Date()) -> (day: Int, week: Int, downtime: TimeInterval, meanRecovery: TimeInterval?) {
        let day = incidents.filter { $0.startedAt >= now.addingTimeInterval(-86_400) }.count; let week = incidents.filter { $0.startedAt >= now.addingTimeInterval(-604_800) }; let recovered = week.filter { $0.endedAt != nil }; let downtime = week.reduce(0) { $0 + ($1.endedAt ?? now).timeIntervalSince($1.startedAt) }; return (day, week.count, downtime, recovered.isEmpty ? nil : recovered.map(\.duration).reduce(0, +) / Double(recovered.count))
    }
    private static func make(_ nodeID: UUID, _ event: MonitoringEvent, _ condition: String, _ affected: [String]) -> Incident { Incident(id: UUID(), nodeID: nodeID, startedAt: event.timestamp, endedAt: nil, severity: event.state == .warning ? .warning : .critical, observableCondition: condition, affectedComponents: affected, timeline: [IncidentTimelineEntry(id: UUID(), timestamp: event.timestamp, state: event.state, message: event.title)], recoveryState: .active) }
    private static func close(_ incident: inout Incident, _ event: MonitoringEvent) { incident.endedAt = event.timestamp; incident.recoveryState = .recovered; incident.timeline.append(IncidentTimelineEntry(id: UUID(), timestamp: event.timestamp, state: .online, message: event.title)) }
    private static func name(_ value: String) -> String { ["wg0":"WireGuard wg0", "adguard":"AdGuard", "antizapret":"AntiZapret", "dnsPublic":"Public DNS", "disk":"Disk", "listeners":"Network listeners"][value] ?? value }
}
