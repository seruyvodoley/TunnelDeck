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
