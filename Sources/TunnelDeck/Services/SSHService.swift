import Foundation

struct SSHConfiguration: Sendable {
    let host: String
    let username: String
    let keyPath: String
    let timeout: Int
    var port: Int = 22
}

struct CommandResult: Sendable {
    let stdout: String
    let stderr: String
    let exitCode: Int32
    let duration: TimeInterval
    var succeeded: Bool { exitCode == 0 }
}

actor SSHService {
    private var processes: [UUID: Process] = [:]
    func activeProcessCount() -> Int { processes.count }

    func execute(_ command: ReadCommand, configuration: SSHConfiguration) async throws -> CommandResult {
        try CommandPolicy.validate(host: configuration.host, username: configuration.username, keyPath: configuration.keyPath)
        return try await run(command: CommandPolicy.authorize(command), configuration: configuration, redact: true)
    }

    func executeHelper(_ command: WriteHelperCommand, configuration: SSHConfiguration) async throws -> CommandResult {
        try CommandPolicy.validate(host: configuration.host, username: configuration.username, keyPath: configuration.keyPath)
        let arguments = try WriteCommandPolicy.arguments(for: command)
        let remoteCommand = arguments.map(Self.shellQuote).joined(separator: " ")
        return try await run(command: remoteCommand, configuration: configuration, redact: true)
    }

    func executeAgent(_ command: AgentReadCommand, configuration: SSHConfiguration) async throws -> CommandResult {
        try CommandPolicy.validate(host: configuration.host, username: configuration.username, keyPath: configuration.keyPath)
        return try await run(command: command.arguments.map(Self.shellQuote).joined(separator: " "), configuration: configuration, redact: true)
    }

    /// Ephemeral raw SSH console command.
    ///
    /// This intentionally bypasses ReadCommand allow-listing because the user
    /// explicitly opted into the interactive server console. It still validates
    /// the selected SSH target and redacts known secret material from stdout /
    /// stderr. Commands are not written to TunnelDeck activity/log history.
    func executeConsole(
        _ rawCommand: String,
        configuration: SSHConfiguration,
        timeout: Int = 300
    ) async throws -> CommandResult {
        try CommandPolicy.validate(
            host: configuration.host,
            username: configuration.username,
            keyPath: configuration.keyPath
        )

        let command = rawCommand.trimmingCharacters(in: .whitespacesAndNewlines)

        guard
            !command.isEmpty,
            command.utf8.count <= 8_192,
            !command.contains("\0")
        else {
            throw CommandPolicyError.deniedCommand
        }

        let seconds = max(5, min(timeout, 300))

        let remoteCommand =
            "/usr/bin/timeout --signal=TERM \(seconds)s /bin/bash -lc " +
            Self.shellQuote(command)

        return try await run(
            command: remoteCommand,
            configuration: configuration,
            redact: true
        )
    }

    func executeHelper2(_ command: Helper2Command, configuration: SSHConfiguration) async throws -> CommandResult {
        try CommandPolicy.validate(host: configuration.host, username: configuration.username, keyPath: configuration.keyPath)
        return try await run(command: Helper2CommandPolicy.arguments(for: command).map(Self.shellQuote).joined(separator: " "), configuration: configuration, redact: true)
    }

    func fetchClientConfig(name: String, configuration: SSHConfiguration) async throws -> String {
        let arguments = try WriteCommandPolicy.arguments(for: .clientConfig(name: name))
        let result = try await run(command: arguments.map(Self.shellQuote).joined(separator: " "), configuration: configuration, redact: false)
        guard result.succeeded else { throw NSError(domain: "TunnelDeck.SSH", code: Int(result.exitCode), userInfo: [NSLocalizedDescriptionKey: SecretRedactor.redact(result.stderr)]) }
        return result.stdout
    }

    func cancelAll() {
        processes.values.filter(\.isRunning).forEach { $0.terminate() }
        processes.removeAll()
    }

    private func cancel(_ identifier: UUID) {
        guard let process = processes[identifier], process.isRunning else { return }
        process.terminate()
    }

    private func finished(_ identifier: UUID) { processes.removeValue(forKey: identifier) }

    func downloadBackup(remotePath: String, destination: URL, configuration: SSHConfiguration) async throws {
        guard remotePath.range(of: #"^/root/tunneldeck-backups/[A-Za-z0-9_-]+$"#, options: .regularExpression) != nil else { throw CommandPolicyError.deniedCommand }
        try CommandPolicy.validate(host: configuration.host, username: configuration.username, keyPath: configuration.keyPath)
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let process = Process(); let error = Pipe(); process.executableURL = URL(fileURLWithPath: "/usr/bin/scp")
        var arguments = ["-r", "-P", String(configuration.port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes"]
        if !configuration.keyPath.isEmpty { arguments += ["-i", configuration.keyPath, "-o", "IdentitiesOnly=yes"] }
        arguments += ["\(configuration.username)@\(configuration.host):\(remotePath)", destination.path]
        process.arguments = arguments; process.standardError = error
        try process.run(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw NSError(domain: "TunnelDeck.SCP", code: Int(process.terminationStatus), userInfo: [NSLocalizedDescriptionKey: SecretRedactor.redact(String(decoding: error.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))]) }
        let downloaded = destination.appendingPathComponent((remotePath as NSString).lastPathComponent)
        if FileManager.default.fileExists(atPath: downloaded.path) {
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: downloaded.path)
            let chmod = Process(); chmod.executableURL = URL(fileURLWithPath: "/bin/chmod"); chmod.arguments = ["-R", "go-rwx", downloaded.path]
            try chmod.run(); chmod.waitUntilExit()
            guard chmod.terminationStatus == 0 else { throw NSError(domain: "TunnelDeck.Permissions", code: Int(chmod.terminationStatus)) }
        }
    }

    private func run(command: String, configuration: SSHConfiguration, redact: Bool) async throws -> CommandResult {
        let identifier = UUID()
        let process = Process()
        let output = Pipe()
        let error = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        var arguments = [
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=\(max(1, min(configuration.timeout, 30)))",
            "-o", "ConnectionAttempts=1",
            "-o", "StrictHostKeyChecking=yes",
            "-p", String(configuration.port)
        ]
        if !configuration.keyPath.isEmpty { arguments += ["-i", configuration.keyPath, "-o", "IdentitiesOnly=yes"] }
        arguments += ["\(configuration.username)@\(configuration.host)", command]
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = error
        let started = Date()
        processes[identifier] = process
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                process.terminationHandler = { [weak self] process in
                    let stdout = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                    let stderr = String(decoding: error.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                    continuation.resume(returning: CommandResult(
                        stdout: redact ? SecretRedactor.redact(stdout) : stdout,
                        stderr: redact ? SecretRedactor.redact(stderr) : stderr,
                        exitCode: process.terminationStatus,
                        duration: Date().timeIntervalSince(started)
                    ))
                    process.terminationHandler = nil
                    Task { await self?.finished(identifier) }
                }
                do { try process.run() } catch {
                    process.terminationHandler = nil
                    processes.removeValue(forKey: identifier)
                    continuation.resume(throwing: error)
                }
            }
        } onCancel: {
            Task { await self.cancel(identifier) }
        }
    }

    private static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
