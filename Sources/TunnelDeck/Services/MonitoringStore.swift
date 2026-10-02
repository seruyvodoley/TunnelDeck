import Foundation

enum MonitoringMetricParser {
    static func pingMilliseconds(_ output: String) -> Double? {
        guard let regex = try? NSRegularExpression(pattern: #"time[=<]([0-9.]+)\s*ms"#) else { return nil }
        let ns = output as NSString
        guard let match = regex.firstMatch(in: output, range: NSRange(location: 0, length: ns.length)),
              match.numberOfRanges > 1 else { return nil }
        return Double(ns.substring(with: match.range(at: 1)))
    }
}

enum MonitoringEventBuilder {
    static func events(from previous: MonitoringSample?, to current: MonitoringSample) -> [MonitoringEvent] {
        guard let previous else { return [] }
        var events: [MonitoringEvent] = []

        if previous.vpsState != current.vpsState {
            events.append(statusEvent(component: "vps", name: "VPS", from: previous.vpsState, to: current.vpsState, at: current.timestamp))
        }

        if previous.vpsState == .online && current.vpsState == .online {
            appendStatusChange(&events, component: "wg0", name: "WireGuard wg0", from: previous.wireGuardState, to: current.wireGuardState, at: current.timestamp)
            appendStatusChange(&events, component: "adguard", name: "AdGuard", from: previous.adGuardState, to: current.adGuardState, at: current.timestamp)
            appendStatusChange(&events, component: "antizapret", name: "AntiZapret", from: previous.antiZapretState, to: current.antiZapretState, at: current.timestamp)
        } else if current.vpsState == .online {
            appendIfStillUnhealthy(&events, component: "wg0", name: "WireGuard wg0", state: current.wireGuardState, at: current.timestamp)
            appendIfStillUnhealthy(&events, component: "adguard", name: "AdGuard", state: current.adGuardState, at: current.timestamp)
            appendIfStillUnhealthy(&events, component: "antizapret", name: "AntiZapret", state: current.antiZapretState, at: current.timestamp)
        }

        if current.vpsState == .online {
            if previous.vpsState == .online {
                if previous.publicDNSExposed != current.publicDNSExposed {
                    if current.publicDNSExposed {
                        events.append(MonitoringEvent(
                            id: UUID(), timestamp: current.timestamp, component: "dnsPublic",
                            title: "Public DNS exposure detected",
                            detail: "A DNS listener is reachable on a public or wildcard address.",
                            state: .critical, recovered: false
                        ))
                    } else {
                        events.append(MonitoringEvent(
                            id: UUID(), timestamp: current.timestamp, component: "dnsPublic",
                            title: "Public DNS exposure cleared",
                            detail: "No public DNS listener is currently detected.",
                            state: .online, recovered: true
                        ))
                    }
                }
                events.append(contentsOf: listenerEvents(from: previous.publicListeners, to: current.publicListeners, at: current.timestamp))
                if diskBand(previous.diskPercent) != diskBand(current.diskPercent) {
                    events.append(diskEvent(percent: current.diskPercent, at: current.timestamp))
                }
            } else {
                if current.publicDNSExposed {
                    events.append(MonitoringEvent(
                        id: UUID(), timestamp: current.timestamp, component: "dnsPublic",
                        title: "Public DNS exposure detected",
                        detail: "DNS is public after VPS connectivity recovered.",
                        state: .critical, recovered: false
                    ))
                }
                if diskBand(current.diskPercent) != .online {
                    events.append(diskEvent(percent: current.diskPercent, at: current.timestamp))
                }
            }
        }

        return events
    }

    private static func appendStatusChange(
        _ events: inout [MonitoringEvent],
        component: String,
        name: String,
        from previous: HealthState,
        to current: HealthState,
        at timestamp: Date
    ) {
        guard previous != current else { return }
        events.append(statusEvent(component: component, name: name, from: previous, to: current, at: timestamp))
    }

    private static func appendIfStillUnhealthy(
        _ events: inout [MonitoringEvent],
        component: String,
        name: String,
        state: HealthState,
        at timestamp: Date
    ) {
        guard state != .online && state != .unknown else { return }
        events.append(MonitoringEvent(
            id: UUID(), timestamp: timestamp, component: component,
            title: "\(name) is not healthy after VPS recovery",
            detail: "Current state: \(state.rawValue).",
            state: state == .offline ? .offline : .warning,
            recovered: false
        ))
    }

    private static func statusEvent(
        component: String,
        name: String,
        from previous: HealthState,
        to current: HealthState,
        at timestamp: Date
    ) -> MonitoringEvent {
        if current == .online && previous != .online {
            return MonitoringEvent(
                id: UUID(), timestamp: timestamp, component: component,
                title: "\(name) recovered",
                detail: "\(previous.rawValue) → online",
                state: .online, recovered: true
            )
        }
        let severity: HealthState = current == .unknown ? .warning : current
        let title: String
        if current == .offline {
            title = "\(name) offline"
        } else if current == .critical {
            title = "\(name) critical"
        } else {
            title = "\(name) state changed"
        }
        return MonitoringEvent(
            id: UUID(), timestamp: timestamp, component: component,
            title: title,
            detail: "\(previous.rawValue) → \(current.rawValue)",
            state: severity, recovered: false
        )
    }

    private static func diskBand(_ percent: Double) -> HealthState {
        if percent >= 90 { return .critical }
        if percent >= 80 { return .warning }
        return .online
    }

    private static func diskEvent(percent: Double, at timestamp: Date) -> MonitoringEvent {
        let state = diskBand(percent)
        if state == .online {
            return MonitoringEvent(
                id: UUID(), timestamp: timestamp, component: "disk",
                title: "Disk usage recovered",
                detail: String(format: "Disk usage is now %.0f%%.", percent),
                state: .online, recovered: true
            )
        }
        return MonitoringEvent(
            id: UUID(), timestamp: timestamp, component: "disk",
            title: state == .critical ? "Disk usage above 90%" : "Disk usage above 80%",
            detail: String(format: "Disk usage is %.0f%%.", percent),
            state: state, recovered: false
        )
    }

    private static func listenerEvents(from previous: [String], to current: [String], at timestamp: Date) -> [MonitoringEvent] {
        let oldSet = Set(previous)
        let newSet = Set(current)
        var events: [MonitoringEvent] = []

        for listener in newSet.subtracting(oldSet).sorted() {
            events.append(MonitoringEvent(
                id: UUID(), timestamp: timestamp, component: "listeners",
                title: "New public listener",
                detail: listener,
                state: .warning, recovered: false
            ))
        }
        for listener in oldSet.subtracting(newSet).sorted() {
            events.append(MonitoringEvent(
                id: UUID(), timestamp: timestamp, component: "listeners",
                title: "Public listener removed",
                detail: listener,
                state: .online, recovered: false
            ))
        }
        return events
    }
}

actor MonitoringHistoryStore {
    private let folder: URL
    private let retention: TimeInterval = 7 * 24 * 60 * 60
    private let minimumSampleInterval: TimeInterval = 30

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        folder = base.appendingPathComponent("TunnelDeck/Monitoring", isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    }

    func loadSamples(host: String) -> [MonitoringSample] {
        decode([MonitoringSample].self, from: samplesURL(host)) ?? []
    }

    func loadEvents(host: String) -> [MonitoringEvent] {
        decode([MonitoringEvent].self, from: eventsURL(host)) ?? []
    }

    func record(host: String, sample: MonitoringSample) -> MonitoringRecordResult {
        var samples = loadSamples(host: host)
        var events = loadEvents(host: host)
        let previous = samples.last
        let newEvents = MonitoringEventBuilder.events(from: previous, to: sample)

        if let last = samples.last, sample.timestamp.timeIntervalSince(last.timestamp) < minimumSampleInterval {
            samples[samples.count - 1] = sample
        } else {
            samples.append(sample)
        }

        let cutoff = sample.timestamp.addingTimeInterval(-retention)
        samples = samples.filter { $0.timestamp >= cutoff }
        events.append(contentsOf: newEvents)
        events = Array(events.suffix(2_000))

        encode(samples, to: samplesURL(host))
        encode(events, to: eventsURL(host))
        return MonitoringRecordResult(samples: samples, events: events, newEvents: newEvents)
    }

    private func key(_ host: String) -> String {
        let value = host.isEmpty ? "unconfigured" : host
        let safe = value.map { character -> Character in
            if character.isLetter || character.isNumber || character == "-" || character == "." { return character }
            return "_"
        }
        return String(safe.prefix(120))
    }

    private func samplesURL(_ host: String) -> URL {
        folder.appendingPathComponent("samples-\(key(host)).json")
    }

    private func eventsURL(_ host: String) -> URL {
        folder.appendingPathComponent("events-\(key(host)).json")
    }

    private func decode<T: Decodable>(_ type: T.Type, from url: URL) -> T? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(type, from: data)
    }

    private func encode<T: Encodable>(_ value: T, to url: URL) {
        guard let data = try? JSONEncoder().encode(value) else { return }
        try? data.write(to: url, options: .atomic)
    }
}
