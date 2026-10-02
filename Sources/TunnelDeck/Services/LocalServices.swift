import AppKit
import Foundation

enum LocalNetworkService {
    static func publicIPv4() async -> String {
        guard let url = URL(string: "https://api.ipify.org"),
              let (data, _) = try? await URLSession.shared.data(from: url),
              let value = String(data: data, encoding: .utf8) else { return "—" }
        return value.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func lanIPv4() -> String {
        var address = "—"
        var pointer: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&pointer) == 0, let first = pointer else { return address }
        defer { freeifaddrs(pointer) }
        for item in sequence(first: first, next: { $0.pointee.ifa_next }) {
            guard item.pointee.ifa_addr.pointee.sa_family == UInt8(AF_INET), String(cString: item.pointee.ifa_name) == "en0" else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            getnameinfo(item.pointee.ifa_addr, socklen_t(item.pointee.ifa_addr.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
            let bytes = host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
            address = String(decoding: bytes, as: UTF8.self)
        }
        return address
    }

    static func open(_ string: String) { if let url = URL(string: string) { NSWorkspace.shared.open(url) } }
}


struct DNSPathSnapshot: Sendable {
    var ran = false
    var state: HealthState = .unknown
    var systemResolvers: [String] = []
    var router = "—"
    var adGuard = "—"
    var testDomain = "pagead2.googlesyndication.com"
    var systemAnswers: [String] = []
    var routerAnswers: [String] = []
    var adGuardAnswers: [String] = []
    var publicAnswers: [String] = []
    var systemUsesAdGuard = false
    var adGuardBlocks = false
    var routerBypasses = false
    var summary = "Not tested"
}

enum DNSPathEvaluator {
    static func parseResolvers(_ output: String) -> [String] {
        var seen = Set<String>()
        return output.split(separator: "\n").compactMap { rawLine in
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard line.hasPrefix("nameserver["),
                  let value = line.split(separator: ":", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces),
                  !value.isEmpty,
                  seen.insert(value).inserted else { return nil }
            return value
        }
    }

    static func parseGateway(_ output: String) -> String {
        for rawLine in output.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("gateway:") {
                return line.split(separator: ":", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces) ?? "—"
            }
        }
        return "—"
    }

    static func isBlocked(_ answers: [String]) -> Bool {
        if answers.isEmpty { return false }
        let normalized = Set(answers.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() })
        return normalized.isSubset(of: ["0.0.0.0", "::", "::0"])
    }

    static func evaluate(
        systemResolvers: [String],
        router: String,
        adGuard: String,
        testDomain: String,
        systemAnswers: [String],
        routerAnswers: [String],
        adGuardAnswers: [String],
        publicAnswers: [String]
    ) -> DNSPathSnapshot {
        var snapshot = DNSPathSnapshot()
        snapshot.ran = true
        snapshot.systemResolvers = systemResolvers
        snapshot.router = router
        snapshot.adGuard = adGuard
        snapshot.testDomain = testDomain
        snapshot.systemAnswers = systemAnswers
        snapshot.routerAnswers = routerAnswers
        snapshot.adGuardAnswers = adGuardAnswers
        snapshot.publicAnswers = publicAnswers
        snapshot.systemUsesAdGuard = systemResolvers.contains(adGuard)
        snapshot.adGuardBlocks = isBlocked(adGuardAnswers)
        snapshot.routerBypasses = router != "—" && snapshot.adGuardBlocks && !routerAnswers.isEmpty && !isBlocked(routerAnswers)

        if adGuard == "—" || adGuard.isEmpty {
            snapshot.state = .warning
            snapshot.summary = "AdGuard VPN address is unavailable."
        } else if !snapshot.adGuardBlocks {
            snapshot.state = .critical
            snapshot.summary = "AdGuard did not block the test domain."
        } else if snapshot.systemUsesAdGuard {
            snapshot.state = .online
            snapshot.summary = snapshot.routerBypasses
                ? "Mac → AdGuard is active and blocking; the router DNS still bypasses AdGuard."
                : "Mac → AdGuard is active and ad blocking is confirmed."
        } else if isBlocked(systemAnswers) {
            snapshot.state = .warning
            snapshot.summary = "The system DNS blocks the test domain, but AdGuard is not listed as a macOS resolver."
        } else {
            snapshot.state = .warning
            snapshot.summary = "AdGuard blocks correctly, but macOS is not currently using it as a system resolver."
        }
        return snapshot
    }
}

actor LocalDNSService {
    func test(adGuardIP: String, testDomain: String = "pagead2.googlesyndication.com") -> DNSPathSnapshot {
        let resolverOutput = run("/usr/sbin/scutil", ["--dns"])
        let routeOutput = run("/sbin/route", ["-n", "get", "default"])
        let resolvers = DNSPathEvaluator.parseResolvers(resolverOutput)
        let gateway = DNSPathEvaluator.parseGateway(routeOutput)

        let systemAnswers = lines(run("/usr/bin/dig", [testDomain, "+short"]))
        let routerAnswers = gateway == "—" ? [] : lines(run("/usr/bin/dig", ["@\(gateway)", testDomain, "+short"]))
        let adGuardAnswers = adGuardIP.isEmpty ? [] : lines(run("/usr/bin/dig", ["@\(adGuardIP)", testDomain, "+short"]))
        let publicAnswers = lines(run("/usr/bin/dig", ["@1.1.1.1", testDomain, "+short"]))

        return DNSPathEvaluator.evaluate(
            systemResolvers: resolvers,
            router: gateway,
            adGuard: adGuardIP.isEmpty ? "—" : adGuardIP,
            testDomain: testDomain,
            systemAnswers: systemAnswers,
            routerAnswers: routerAnswers,
            adGuardAnswers: adGuardAnswers,
            publicAnswers: publicAnswers
        )
    }

    private func run(_ executable: String, _ arguments: [String]) -> String {
        let process = Process()
        let output = Pipe()
        let error = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.standardOutput = output
        process.standardError = error
        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return "" }
            return String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        } catch {
            return ""
        }
    }

    private func lines(_ output: String) -> [String] {
        output.split(separator: "\n").map { String($0).trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }
}

actor DiagnosticHistoryStore {
    private let url: URL
    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let folder = base.appendingPathComponent("TunnelDeck", isDirectory: true)
        try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        url = folder.appendingPathComponent("diagnostics.json")
    }
    func load() -> [DiagnosticResult] { (try? Data(contentsOf: url)).flatMap { try? JSONDecoder().decode([DiagnosticResult].self, from: $0) } ?? [] }
    func append(_ result: DiagnosticResult) {
        var values = load(); values.append(result)
        if let data = try? JSONEncoder().encode(Array(values.suffix(500))) { try? data.write(to: url, options: .atomic) }
    }
}