import Foundation

/// Stable identity used only while decoding pre-2.0 monitoring JSON. The importer
/// replaces it with the matching node identifier before writing to SQLite.
enum LegacyNodeIdentity {
    static let unassigned = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
}

enum NodeRole: String, Codable, Sendable, CaseIterable { case primary, gateway, dns, relay, auxiliary, custom }
enum ServiceKind: String, Codable, Sendable { case ssh, wireGuard, adGuard, antiZapret, openVPN, system, other }
enum TransportProtocol: String, Codable, Sendable { case tcp, udp, unknown }
enum AddressFamily: String, Codable, Sendable { case ipv4, ipv6, dualStack, unknown }
enum ExposureClassification: String, Codable, Sendable, CaseIterable { case publicInternet, vpnOnly, privateLAN, loopback, firewallBlocked, unknown }
enum IncidentSeverity: String, Codable, Sendable { case info, warning, critical }
enum IncidentRecoveryState: String, Codable, Sendable { case active, recovered, acknowledged }
enum DriftChangeKind: String, Codable, Sendable { case added, removed, changed }
enum AlertRuleKind: String, Codable, Sendable, CaseIterable { case nodeOffline, serviceOffline, disk, memory, ping, publicDNS, newPublicListener, peerInactive, configurationDrift }

struct InfrastructureNode: Identifiable, Codable, Sendable, Hashable {
    let id: UUID
    var name: String
    var role: NodeRole
    var customRole: String?
    var host: String
    var sshPort: Int
    var createdAt: Date
    var updatedAt: Date
    var enabled: Bool
}

struct ServiceInstance: Identifiable, Codable, Sendable, Hashable {
    let id: UUID; let nodeID: UUID; var kind: ServiceKind; var name: String; var unitName: String?; var state: HealthState; var observedAt: Date?
}

struct NetworkEndpoint: Identifiable, Codable, Sendable, Hashable {
    let id: UUID; let nodeID: UUID; var serviceID: UUID?; var protocolName: TransportProtocol; var port: Int; var bindAddresses: [String]; var addressFamily: AddressFamily; var firewallEvidence: [String]; var classification: ExposureClassification; var explanation: String; var observedAt: Date
}

struct WireGuardInterface: Identifiable, Codable, Sendable, Hashable {
    let id: UUID; let nodeID: UUID; var name: String; var addresses: [String]; var listenPort: Int?; var mtu: Int?; var publicIdentifier: String?; var state: HealthState
}

struct DNSResolver: Identifiable, Codable, Sendable, Hashable {
    let id: UUID; let nodeID: UUID; var serviceID: UUID?; var name: String; var bindAddresses: [String]; var port: Int; var state: HealthState
}

struct InfrastructureEvent: Identifiable, Codable, Sendable, Hashable {
    let id: UUID; let nodeID: UUID; var timestamp: Date; var componentID: String; var kind: String; var title: String; var detail: String; var state: HealthState; var isRecovery: Bool
}

struct IncidentTimelineEntry: Identifiable, Codable, Sendable, Hashable {
    let id: UUID; var timestamp: Date; var state: HealthState; var message: String
}

struct Incident: Identifiable, Codable, Sendable, Hashable {
    let id: UUID; let nodeID: UUID; var startedAt: Date; var endedAt: Date?; var severity: IncidentSeverity; var observableCondition: String; var affectedComponents: [String]; var timeline: [IncidentTimelineEntry]; var recoveryState: IncidentRecoveryState
    var duration: TimeInterval { (endedAt ?? Date()).timeIntervalSince(startedAt) }
}

struct AlertRule: Identifiable, Codable, Sendable, Hashable {
    let id: UUID; let nodeID: UUID; var kind: AlertRuleKind; var enabled: Bool; var threshold: Double?; var severity: IncidentSeverity; var cooldown: TimeInterval; var muteUntil: Date?; var acknowledgedAt: Date?
}

struct ConfigurationBaseline: Identifiable, Codable, Sendable, Hashable {
    let id: UUID; let nodeID: UUID; var createdAt: Date; var publicListeners: [String]; var services: [String]; var ports: [Int]; var wireGuardInterfaces: [String]; var peerPublicIdentifiers: [String]; var dnsBinds: [String]; var sshPolicy: [String: String]; var configurationHashes: [String: String]
}

struct ConfigurationDrift: Identifiable, Codable, Sendable, Hashable {
    let id: UUID; let nodeID: UUID; let baselineID: UUID; var detectedAt: Date; var kind: DriftChangeKind; var category: String; var key: String; var previousValue: String?; var currentValue: String?
}

struct BackupSnapshot: Identifiable, Codable, Sendable, Hashable {
    let id: UUID; let nodeID: UUID; var createdAt: Date; var operation: String; var remoteIdentifier: String; var size: Int64; var verified: Bool
}

enum LegacyModelAdapter {
    static func node(from profile: ServerProfile, now: Date = Date()) -> InfrastructureNode {
        InfrastructureNode(id: profile.id, name: profile.name, role: role(profile.role), customRole: role(profile.role) == .custom ? profile.role : nil, host: profile.host, sshPort: profile.port, createdAt: now, updatedAt: now, enabled: true)
    }

    static func role(_ value: String) -> NodeRole {
        switch value.lowercased() {
        case "primary": return .primary
        case "gateway": return .gateway
        case "dns": return .dns
        case "relay": return .relay
        case "auxiliary": return .auxiliary
        default: return .custom
        }
    }

    static func event(from event: MonitoringEvent, nodeID: UUID) -> InfrastructureEvent {
        InfrastructureEvent(id: event.id, nodeID: nodeID, timestamp: event.timestamp, componentID: event.component, kind: "monitoring", title: event.title, detail: event.detail, state: event.state, isRecovery: event.recovered)
    }
}
