import Foundation

enum HealthState: String, Codable, Sendable { case online, warning, offline, unknown }

struct AppSettings: Codable, Sendable, Equatable {
    var host = ""
    var username = "root"
    var port = 22
    var keyPath = "~/.ssh/id_ed25519"
    var pollingEnabled = false
    var pollingInterval = 5.0
    var handshakeTimeout = 180.0
    var completedOnboarding = false
    var writeModeEnabled = false
    var notificationsEnabled = false
    var launchAtLogin = false
}

struct SystemSnapshot: Sendable {
    var health: HealthState = .unknown
    var sshAvailable = false
    var pingMilliseconds: Double?
    var hostname = "—"
    var osVersion = "—"
    var kernel = "—"
    var uptime = "—"
    var cpuPercent: Double = 0
    var memoryPercent: Double = 0
    var diskPercent: Double = 0
    var loadAverage = "—"
    var publicIPv4 = "—"
    var publicIPv6 = "—"
    var macPublicIP = "—"
    var macLANIP = "—"
}

struct WireGuardPeer: Identifiable, Sendable, Hashable {
    let id: String
    var name: String
    var vpnIP: String
    var publicKey: String
    var endpoint: String
    var latestHandshake: Date?
    var receivedBytes: UInt64
    var sentBytes: UInt64
    var status: HealthState
    var managedBy = "Existing"
}

struct BackupRecord: Identifiable, Codable, Sendable, Hashable {
    var id: String { path }
    let timestamp: String
    let operation: String
    let hostname: String
    let tunnelDeckVersion: String
    let files: [BackupFile]
    let preHealth: [String: StringValue]
    let path: String
    let size: Int64
}

struct BackupFile: Codable, Sendable, Hashable { let path: String; let backupPath: String; let sha256: String; let size: Int64 }

enum StringValue: Codable, Sendable, Hashable {
    case string(String), bool(Bool), number(Double), null
    init(from decoder: Decoder) throws {
        let box = try decoder.singleValueContainer()
        if box.decodeNil() { self = .null }
        else if let value = try? box.decode(Bool.self) { self = .bool(value) }
        else if let value = try? box.decode(Double.self) { self = .number(value) }
        else { self = .string(try box.decode(String.self)) }
    }
    func encode(to encoder: Encoder) throws {
        var box = encoder.singleValueContainer()
        switch self { case .string(let value): try box.encode(value); case .bool(let value): try box.encode(value); case .number(let value): try box.encode(value); case .null: try box.encodeNil() }
    }
}

struct AppError: Identifiable, Error, Sendable {
    let id = UUID()
    let title: String
    let message: String
    let technicalDetails: String
    let recommendedAction: String
}

struct WireGuardSnapshot: Sendable {
    var state: HealthState = .unknown
    var interface = "wg0"
    var address = "—"
    var listenPort = "—"
    var mtu = "—"
    var publicKey = "—"
    var receivedBytes: UInt64 = 0
    var sentBytes: UInt64 = 0
    var peers: [WireGuardPeer] = []
}

struct UnitStatus: Identifiable, Sendable, Hashable {
    var id: String { name }
    let name: String
    let activeState: String
    let subState: String
    var health: HealthState { activeState == "active" ? .online : (activeState == "inactive" ? .warning : .offline) }
}

struct Listener: Identifiable, Sendable, Hashable {
    var id: String { "\(protocolName)-\(address)-\(port)" }
    let protocolName: String
    let address: String
    let port: Int
    let process: String
    var isPublic: Bool { address == "0.0.0.0" || address == "::" || address == "[::]" }
}

struct ProfileMetadata: Identifiable, Sendable, Hashable {
    var id: String { path }
    let name: String
    let type: String
    let endpoint: String
    let port: String
    let dns: String
    let allowedIPs: String
    let mtu: String
    let modified: String
    let path: String
    let category: String
}

struct LogEntry: Identifiable, Sendable {
    let id = UUID()
    let timestamp: Date
    let subsystem: String
    let command: String
    let stdout: String
    let stderr: String
    let exitCode: Int32
}

struct DiagnosticResult: Identifiable, Codable, Sendable {
    let id: UUID
    let date: Date
    let name: String
    let success: Bool
    let summary: String
    let milliseconds: Double?
}
