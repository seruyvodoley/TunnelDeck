import Foundation

struct FleetNodeSummary: Identifiable, Sendable {
    let id: UUID; var name: String; var role: String; var overall: HealthState; var ssh: HealthState; var wireGuard: HealthState; var adGuard: HealthState; var antiZapret: HealthState; var cpu: Double?; var memory: Double?; var disk: Double?; var ping: Double?; var peersOnline: Int?; var peersTotal: Int?; var exposureWarnings: Int; var activeIncidents: Int; var lastObservedAt: Date?
}

@MainActor final class FleetController {
    func summaries(profiles: [ServerProfile], activeID: UUID?, system: SystemSnapshot, wireGuard: WireGuardSnapshot, units: [UnitStatus], security: SecuritySnapshot, incidents: [Incident], lastKnownSamples:[UUID:MonitoringSample]) -> [FleetNodeSummary] {
        profiles.map { profile in
            guard profile.id == activeID else { let sample=lastKnownSamples[profile.id];return FleetNodeSummary(id: profile.id, name: profile.name, role: profile.role, overall: sample?.vpsState ?? .unknown, ssh: sample?.vpsState ?? .unknown, wireGuard: sample?.wireGuardState ?? .unknown, adGuard: sample?.adGuardState ?? .unknown, antiZapret: sample?.antiZapretState ?? .unknown, cpu: sample?.cpuPercent, memory: sample?.memoryPercent, disk: sample?.diskPercent, ping: sample?.pingMilliseconds, peersOnline: nil, peersTotal: nil, exposureWarnings: sample?.publicListeners.count ?? 0, activeIncidents: incidents.filter { $0.nodeID == profile.id && $0.recoveryState == .active }.count, lastObservedAt: sample?.timestamp) }
            let adGuard = state(units, { $0.name.localizedCaseInsensitiveContains("AdGuardHome") }, system.sshAvailable)
            let antiZapret = state(units, { $0.name == "antizapret.service" }, system.sshAvailable)
            let overall = [system.health, wireGuard.state, adGuard, antiZapret, security.state].max(by: { rank($0) < rank($1) }) ?? .unknown
            return FleetNodeSummary(id: profile.id, name: profile.name, role: profile.role, overall: overall, ssh: system.sshAvailable ? .online : system.health == .offline ? .offline : .unknown, wireGuard: wireGuard.state, adGuard: adGuard, antiZapret: antiZapret, cpu: system.cpuPercent, memory: system.memoryPercent, disk: system.diskPercent, ping: system.pingMilliseconds, peersOnline: wireGuard.peers.filter { $0.status == .online }.count, peersTotal: wireGuard.peers.count, exposureWarnings: security.publicListeners.filter { $0.state == .warning || $0.state == .critical }.count, activeIncidents: incidents.filter { $0.nodeID == profile.id && $0.recoveryState == .active }.count, lastObservedAt: lastKnownSamples[profile.id]?.timestamp)
        }
    }
    private func state(_ units: [UnitStatus], _ predicate: (UnitStatus) -> Bool, _ nodeOnline: Bool) -> HealthState { guard nodeOnline else { return .unknown }; guard let unit = units.first(where: predicate) else { return .unknown }; return unit.activeState == "active" ? .online : .offline }
    private func rank(_ state: HealthState) -> Int { switch state { case .online: 0; case .unknown: 1; case .warning: 2; case .critical: 3; case .offline: 4 } }
}
