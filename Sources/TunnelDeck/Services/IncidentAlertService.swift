import Foundation

struct AlertEvaluationResult: Sendable {
    let triggers: [AlertTrigger]
}

enum IncidentEngine {
    static func build(from events: [MonitoringEvent]) -> [MonitoringIncident] {
        let sorted = events.sorted { $0.timestamp < $1.timestamp }
        var incidents: [MonitoringIncident] = []
        var open: [String: Int] = [:]

        func key(for event: MonitoringEvent) -> String {
            if event.component == "listeners" { return "listeners:\(event.detail)" }
            return event.component
        }

        for event in sorted {
            let incidentKey = key(for: event)
            let isRecovery = event.recovered || event.title == "Public listener removed" || event.title.contains("recovered") || event.title.contains("cleared")

            if isRecovery {
                if let index = open[incidentKey] {
                    incidents[index].end = event.timestamp
                    incidents[index].timeline.append(event)
                    open.removeValue(forKey: incidentKey)
                }
                continue
            }

            let startsIncident = event.state == .offline || event.state == .critical || event.state == .warning
            guard startsIncident else { continue }

            if let index = open[incidentKey] {
                incidents[index].timeline.append(event)
                if !incidents[index].affectedComponents.contains(event.component) {
                    incidents[index].affectedComponents.append(event.component)
                }
                continue
            }

            let incident = MonitoringIncident(
                id: "\(incidentKey)|\(event.timestamp.timeIntervalSince1970)",
                component: event.component,
                title: incidentTitle(event),
                start: event.timestamp,
                end: nil,
                severity: event.state,
                affectedComponents: [event.component],
                timeline: [event]
            )
            incidents.append(incident)
            open[incidentKey] = incidents.count - 1
        }
        return incidents
    }

    private static func incidentTitle(_ event: MonitoringEvent) -> String {
        switch event.component {
        case "vps": return "VPS connectivity outage"
        case "wg0": return "WireGuard availability incident"
        case "adguard": return "AdGuard availability incident"
        case "antizapret": return "AntiZapret availability incident"
        case "dnsPublic": return "Public DNS exposure"
        case "disk": return "Disk pressure"
        case "listeners": return "Unexpected public listener · \(event.detail)"
        default: return event.title
        }
    }
}

enum AlertRuleDefaults {
    static var rules: [AlertRule] {
        [
            AlertRule(id: stableID("vps"), kind: .vpsOffline, title: "VPS offline", enabled: true, threshold: nil, cooldownMinutes: 10),
            AlertRule(id: stableID("wg0"), kind: .wireGuardOffline, title: "WireGuard offline", enabled: true, threshold: nil, cooldownMinutes: 10),
            AlertRule(id: stableID("services"), kind: .serviceOffline, title: "AdGuard / AntiZapret offline", enabled: true, threshold: nil, cooldownMinutes: 10),
            AlertRule(id: stableID("dns"), kind: .publicDNS, title: "Public DNS exposure", enabled: true, threshold: nil, cooldownMinutes: 30),
            AlertRule(id: stableID("listener"), kind: .newPublicListener, title: "New public listener", enabled: true, threshold: nil, cooldownMinutes: 30),
            AlertRule(id: stableID("disk"), kind: .diskPercent, title: "Disk usage", enabled: true, threshold: 80, cooldownMinutes: 60),
            AlertRule(id: stableID("ping"), kind: .pingMilliseconds, title: "High ping", enabled: false, threshold: 150, cooldownMinutes: 30)
        ]
    }

    private static func stableID(_ name: String) -> UUID {
        let values: [String: UUID] = [
            "vps": UUID(uuidString: "00000000-0000-4000-8000-000000000101")!,
            "wg0": UUID(uuidString: "00000000-0000-4000-8000-000000000102")!,
            "services": UUID(uuidString: "00000000-0000-4000-8000-000000000103")!,
            "dns": UUID(uuidString: "00000000-0000-4000-8000-000000000104")!,
            "listener": UUID(uuidString: "00000000-0000-4000-8000-000000000105")!,
            "disk": UUID(uuidString: "00000000-0000-4000-8000-000000000106")!,
            "ping": UUID(uuidString: "00000000-0000-4000-8000-000000000107")!
        ]
        return values[name]!
    }
}

actor AlertRuleStore {
    private let folder: URL

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        folder = base.appendingPathComponent("TunnelDeck/Alerts", isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    }

    func load(host: String) -> [AlertRule] {
        let url = fileURL(host)
        guard let data = try? Data(contentsOf: url),
              let decoded = try? JSONDecoder().decode([AlertRule].self, from: data) else {
            return AlertRuleDefaults.rules
        }
        let defaults = AlertRuleDefaults.rules
        var byKind = Dictionary(uniqueKeysWithValues: decoded.map { ($0.kind, $0) })
        for item in defaults where byKind[item.kind] == nil { byKind[item.kind] = item }
        return defaults.compactMap { byKind[$0.kind] }
    }

    func save(host: String, rules: [AlertRule]) {
        guard let data = try? JSONEncoder().encode(rules) else { return }
        try? data.write(to: fileURL(host), options: .atomic)
    }

    private func fileURL(_ host: String) -> URL {
        let safe = String((host.isEmpty ? "unconfigured" : host).map {
            ($0.isLetter || $0.isNumber || $0 == "-" || $0 == ".") ? $0 : "_"
        }.prefix(120))
        return folder.appendingPathComponent("rules-\(safe).json")
    }
}

enum AlertRuleEngine {
    static func evaluate(
        previous: MonitoringSample?,
        current: MonitoringSample,
        newEvents: [MonitoringEvent],
        rules: [AlertRule],
        lastFired: [String: Double],
        now: Date
    ) -> AlertEvaluationResult {
        var triggers: [AlertTrigger] = []
        let enabled = rules.filter(\.enabled)

        for rule in enabled {
            switch rule.kind {
            case .diskPercent:
                guard let threshold = rule.threshold, let previous else { continue }
                let wasHigh = previous.diskPercent >= threshold
                let isHigh = current.diskPercent >= threshold
                if !wasHigh && isHigh && cooldownAllows(rule, lastFired: lastFired, now: now) {
                    triggers.append(AlertTrigger(ruleID: rule.id, title: "Disk usage alert", detail: String(format: "Disk usage %.0f%% crossed the %.0f%% threshold.", current.diskPercent, threshold), recovered: false))
                } else if wasHigh && !isHigh {
                    triggers.append(AlertTrigger(ruleID: rule.id, title: "Disk usage recovered", detail: String(format: "Disk usage is back to %.0f%%.", current.diskPercent), recovered: true))
                }
            case .pingMilliseconds:
                guard let threshold = rule.threshold, let previous else { continue }
                let old = previous.pingMilliseconds ?? 0
                let new = current.pingMilliseconds ?? 0
                if old < threshold && new >= threshold && cooldownAllows(rule, lastFired: lastFired, now: now) {
                    triggers.append(AlertTrigger(ruleID: rule.id, title: "High latency", detail: String(format: "Ping %.0f ms crossed the %.0f ms threshold.", new, threshold), recovered: false))
                } else if old >= threshold && new > 0 && new < threshold {
                    triggers.append(AlertTrigger(ruleID: rule.id, title: "Latency recovered", detail: String(format: "Ping is back to %.0f ms.", new), recovered: true))
                }
            default:
                for event in newEvents where matches(rule.kind, event: event) {
                    if event.recovered || cooldownAllows(rule, lastFired: lastFired, now: now) {
                        triggers.append(AlertTrigger(ruleID: rule.id, title: event.title, detail: event.detail, recovered: event.recovered))
                    }
                }
            }
        }
        return AlertEvaluationResult(triggers: triggers)
    }

    private static func matches(_ kind: AlertRuleKind, event: MonitoringEvent) -> Bool {
        switch kind {
        case .vpsOffline: return event.component == "vps"
        case .wireGuardOffline: return event.component == "wg0"
        case .serviceOffline: return event.component == "adguard" || event.component == "antizapret"
        case .publicDNS: return event.component == "dnsPublic"
        case .newPublicListener: return event.component == "listeners"
        case .diskPercent, .pingMilliseconds: return false
        }
    }

    private static func cooldownAllows(_ rule: AlertRule, lastFired: [String: Double], now: Date) -> Bool {
        guard let timestamp = lastFired[rule.id.uuidString] else { return true }
        return now.timeIntervalSince1970 - timestamp >= Double(rule.cooldownMinutes * 60)
    }
}
