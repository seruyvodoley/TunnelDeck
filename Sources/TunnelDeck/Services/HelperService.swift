import Foundation

struct HelperStatus: Codable, Sendable { let version: String }
struct HelperPeer: Codable, Sendable, Identifiable {
    var id: String { publicKey }
    let publicKey: String; let name: String; let ip: String; let endpoint: String; let latestHandshake: Int64; let rx: UInt64; let tx: UInt64; let managedBy: String; let created: String?
}
struct HelperPeerChange: Codable, Sendable { let name: String?; let ip: String?; let publicKey: String?; let clientPath: String?; let backup: String }
struct HelperServiceChange: Codable, Sendable { let unit: String; let action: String; let state: String; let backup: String }

actor HelperService {
    static let localVersion = "1.0.0"
    private let ssh: SSHService
    init(ssh: SSHService) { self.ssh = ssh }

    func version(configuration: SSHConfiguration) async -> Result<String, AppError> {
        do {
            let result = try await ssh.executeHelper(.version, configuration: configuration)
            guard result.succeeded else {
                return .failure(AppError(title: "Server helper not installed", message: "TunnelDeck helper could not be executed on the VPS.", technicalDetails: result.stderr, recommendedAction: "Review the helper source and use Install Helper after SSH access is working."))
            }
            return .success(try JSONDecoder().decode(HelperStatus.self, from: Data(result.stdout.utf8)).version)
        } catch {
            return .failure(AppError(title: "Helper check failed", message: "TunnelDeck could not determine the helper version.", technicalDetails: error.localizedDescription, recommendedAction: "Verify SSH access and host fingerprint."))
        }
    }

    func listBackups(configuration: SSHConfiguration) async throws -> [BackupRecord] {
        let result = try await ssh.executeHelper(.listBackups, configuration: configuration)
        guard result.succeeded else { throw NSError(domain: "TunnelDeck.Helper", code: Int(result.exitCode), userInfo: [NSLocalizedDescriptionKey: result.stderr]) }
        return try JSONDecoder().decode([BackupRecord].self, from: Data(result.stdout.utf8))
    }

    func peers(configuration: SSHConfiguration) async throws -> [HelperPeer] {
        let result = try await ssh.executeHelper(.wireGuardList, configuration: configuration)
        guard result.succeeded else { throw NSError(domain: "TunnelDeck.Helper", code: Int(result.exitCode), userInfo: [NSLocalizedDescriptionKey: result.stderr]) }
        return try JSONDecoder().decode([HelperPeer].self, from: Data(result.stdout.utf8))
    }

    func addPeer(name: String, ip: String, dns: String, mtu: Int, allowedIPs: String, endpoint: String, configuration: SSHConfiguration) async throws -> HelperPeerChange {
        let result = try await ssh.executeHelper(.addPeer(name: name, ip: ip, dns: dns, mtu: mtu, allowedIPs: allowedIPs, endpoint: endpoint), configuration: configuration)
        guard result.succeeded else { throw NSError(domain: "TunnelDeck.Helper", code: Int(result.exitCode), userInfo: [NSLocalizedDescriptionKey: result.stderr]) }
        return try JSONDecoder().decode(HelperPeerChange.self, from: Data(result.stdout.utf8))
    }

    func removePeer(publicKey: String, deleteClient: Bool, allowExisting: Bool, configuration: SSHConfiguration) async throws -> HelperPeerChange {
        let result = try await ssh.executeHelper(.removePeer(publicKey: publicKey, deleteClient: deleteClient, allowExisting: allowExisting), configuration: configuration)
        guard result.succeeded else { throw NSError(domain: "TunnelDeck.Helper", code: Int(result.exitCode), userInfo: [NSLocalizedDescriptionKey: result.stderr]) }
        return try JSONDecoder().decode(HelperPeerChange.self, from: Data(result.stdout.utf8))
    }

    func service(action: String, unit: String, configuration: SSHConfiguration) async throws -> HelperServiceChange {
        let normalized = unit.hasSuffix(".service") ? String(unit.dropLast(8)) : unit
        let result = try await ssh.executeHelper(.service(action: action, unit: normalized), configuration: configuration)
        guard result.succeeded else { throw NSError(domain: "TunnelDeck.Helper", code: Int(result.exitCode), userInfo: [NSLocalizedDescriptionKey: result.stderr]) }
        return try JSONDecoder().decode(HelperServiceChange.self, from: Data(result.stdout.utf8))
    }
}

protocol ServerTransaction: Sendable {
    associatedtype Preview: Sendable
    associatedtype Output: Sendable
    func prepare() async throws
    func backup() async throws -> String
    func preview() async throws -> Preview
    func apply() async throws -> Output
    func validate() async throws
    func rollback() async throws
}

struct TransactionResult<Output: Sendable>: Sendable {
    let output: Output?
    let backup: String?
    let rolledBack: Bool
    let error: String?
}

enum TransactionRunner {
    static func run<T: ServerTransaction>(_ transaction: T) async -> TransactionResult<T.Output> {
        do {
            try await transaction.prepare()
            let backup = try await transaction.backup()
            _ = try await transaction.preview()
            let output = try await transaction.apply()
            do {
                try await transaction.validate()
                return TransactionResult(output: output, backup: backup, rolledBack: false, error: nil)
            } catch {
                try await transaction.rollback()
                return TransactionResult(output: nil, backup: backup, rolledBack: true, error: error.localizedDescription)
            }
        } catch {
            return TransactionResult(output: nil, backup: nil, rolledBack: false, error: error.localizedDescription)
        }
    }
}
