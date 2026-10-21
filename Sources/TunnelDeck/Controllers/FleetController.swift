import Foundation

struct FleetNodeSummary: Identifiable, Sendable {
    let id: UUID; var name: String; var role: String; var overall: HealthState; var ssh: HealthState; var wireGuard: HealthState; var adGuard: HealthState; var antiZapret: HealthState; var cpu: Double?; var memory: Double?; var disk: Double?; var ping: Double?; var peersOnline: Int?; var peersTotal: Int?; var exposureWarnings: Int; var activeIncidents: Int; var lastObservedAt: Date?
}

@MainActor final class FleetController {
    func summaries(profiles: [ServerProfile], activeID: UUID?, activeLastObservedAt: Date?, staleAfter: TimeInterval, system: SystemSnapshot, wireGuard: WireGuardSnapshot, units: [UnitStatus], security: SecuritySnapshot, incidents: [Incident], lastKnownSamples:[UUID:MonitoringSample]) -> [FleetNodeSummary] {
        profiles.map { profile in
            guard profile.id == activeID else {
                let sample=lastKnownSamples[profile.id]
                let isFresh=sample.map{Date().timeIntervalSince($0.timestamp)<=staleAfter} ?? false
                let state: (HealthState) -> HealthState = { isFresh ? $0 : .unknown }
                return FleetNodeSummary(id: profile.id, name: profile.name, role: profile.role, overall: state(sample?.vpsState ?? .unknown), ssh: state(sample?.vpsState ?? .unknown), wireGuard: state(sample?.wireGuardState ?? .unknown), adGuard: state(sample?.adGuardState ?? .unknown), antiZapret: state(sample?.antiZapretState ?? .unknown), cpu: sample?.cpuPercent, memory: sample?.memoryPercent, disk: sample?.diskPercent, ping: sample?.pingMilliseconds, peersOnline: nil, peersTotal: nil, exposureWarnings: sample?.publicListeners.count ?? 0, activeIncidents: incidents.filter { $0.nodeID == profile.id && $0.recoveryState == .active }.count, lastObservedAt: sample?.timestamp)
            }
            let adGuard = state(units, { $0.name.localizedCaseInsensitiveContains("AdGuardHome") }, system.sshAvailable)
            let antiZapret = state(units, { $0.name == "antizapret.service" }, system.sshAvailable)
            return FleetNodeSummary(id: profile.id, name: profile.name, role: profile.role, overall: system.health, ssh: system.sshAvailable ? .online : system.health == .offline ? .offline : .unknown, wireGuard: wireGuard.state, adGuard: adGuard, antiZapret: antiZapret, cpu: system.cpuPercent, memory: system.memoryPercent, disk: system.diskPercent, ping: system.pingMilliseconds, peersOnline: wireGuard.peers.filter { $0.status == .online }.count, peersTotal: wireGuard.peers.count, exposureWarnings: security.publicListeners.filter { $0.state == .warning || $0.state == .critical }.count, activeIncidents: incidents.filter { $0.nodeID == profile.id && $0.recoveryState == .active }.count, lastObservedAt: activeLastObservedAt)
        }
    }
    private func state(_ units: [UnitStatus], _ predicate: (UnitStatus) -> Bool, _ nodeOnline: Bool) -> HealthState { guard nodeOnline else { return .unknown }; guard let unit = units.first(where: predicate) else { return .unknown }; return unit.activeState == "active" ? .online : .offline }
}
