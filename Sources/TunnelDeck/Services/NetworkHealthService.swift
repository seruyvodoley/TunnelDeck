import Foundation

enum NetworkProbeState: String, Sendable {
    case passed, warning, failed, unknown
}

struct NetworkProbe: Identifiable, Sendable {
    let id: String
    let title: String
    let state: NetworkProbeState
    let detail: String
}

struct NetworkHealthSnapshot: Sendable {
    let checkedAt: Date
    let host: String
    let probes: [NetworkProbe]

    static func parse(_ output: String, succeeded: Bool, now: Date = Date()) -> NetworkHealthSnapshot {
        let sections = TaggedDiscoveryOutput.sections(output)
        guard succeeded else {
            return NetworkHealthSnapshot(checkedAt: now, host: "Unknown", probes: [
                NetworkProbe(id: "ssh", title: "VPS read-only probe", state: .failed,
                            detail: "SSH command failed; no network state was changed.")
            ])
        }
        let rawHost = sections["HOST"]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let host = rawHost.isEmpty ? "Unknown" : rawHost
        let mainRoute = firstLine(sections["ROUTE_MAIN"])
        let ruRoute = firstLine(sections["ROUTE_RU_MARK"])
        let dns = firstLine(sections["DNS"])
        let https = sections["HTTPS"]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let xray = keyValues(sections["XRAY"] ?? "")
        let xrayListener = firstLine(sections["XRAY_LISTENER"])
        let xhttp = keyValues(sections["XHTTP_SERVICE"] ?? "")
        let xhttpListener = firstLine(sections["XHTTP_LISTENER"])
        let xhttpInstalled = xhttp["LoadState"] == "loaded"
        let xhttpActive = xhttp["ActiveState"] == "active" && xhttp["SubState"] == "running"
        let xhttpState: NetworkProbeState = !xhttpInstalled ? .unknown : (xhttpActive && !xhttpListener.isEmpty ? .passed:.warning)
        let xhttpTLS = keyValues(sections["XHTTP_TLS_SERVICE"] ?? "")
        let xhttpTLSListener = firstLine(sections["XHTTP_TLS_LISTENER"])
        let xhttpTLSRoute = firstLine(sections["XHTTP_TLS_CADDY_ROUTE"]) == "configured"
        let xhttpTLSCaddyReady = firstLine(sections["XHTTP_TLS_CADDY"]) == "ready"
        let xhttpTLSInstalled = xhttpTLS["LoadState"] == "loaded"
        let xhttpTLSActive = xhttpTLS["ActiveState"] == "active" && xhttpTLS["SubState"] == "running"
        let xhttpTLSState: NetworkProbeState = !xhttpTLSInstalled ? .unknown : (xhttpTLSActive && !xhttpTLSListener.isEmpty && xhttpTLSRoute && xhttpTLSCaddyReady ? .passed:.warning)
        let caddy = sections["CADDY_CONTAINER"]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let resources = (sections["RESOURCES"] ?? "").replacingOccurrences(of: "\n", with: " · ")
        let resourceValues = keyValues(sections["RESOURCES"] ?? "")
        let availableMemory = UInt64(resourceValues["memory_available_bytes"] ?? "")
        let diskUsed = Int(resourceValues["disk_used_percent"]?.trimmingCharacters(in: CharacterSet(charactersIn: "%")) ?? "")
        let swapUsed = Int(resourceValues["swap_used_percent"]?.trimmingCharacters(in: CharacterSet(charactersIn: "%")) ?? "")
        let resourceState: NetworkProbeState = {
            guard availableMemory != nil || diskUsed != nil else { return .unknown }
            if (availableMemory ?? UInt64.max) < 256 * 1024 * 1024 || (diskUsed ?? 0) >= 90 || (swapUsed ?? 0) >= 90 { return .warning }
            return .passed
        }()

        return NetworkHealthSnapshot(checkedAt: now, host: host, probes: [
            NetworkProbe(id: "main-route", title: "VPS default route", state: mainRoute.contains("dev ens3") ? .passed : .warning,
                        detail: mainRoute.isEmpty ? "No route evidence" : mainRoute),
            NetworkProbe(id: "ru-policy", title: "RU policy route lookup", state: ruRoute.contains("dev homeexit") ? .passed : .warning,
                        detail: ruRoute.isEmpty ? "Lookup with mark 0x67 returned no route evidence" : "mark 0x67: \(ruRoute) (route lookup only; no packet injected)"),
            NetworkProbe(id: "dns", title: "VPS DNS resolution", state: dns.isEmpty || ["not known", "temporary failure", "could not resolve", "no address associated"].contains(where: { dns.lowercased().contains($0) }) ? .failed : .passed,
                        detail: dns.isEmpty ? "No DNS answer" : dns),
            NetworkProbe(id: "https", title: "VPS HTTPS request", state: httpsOK(https) ? .passed : .failed,
                        detail: https.isEmpty ? "HTTPS probe returned no result" : https),
            NetworkProbe(id: "xray", title: "Xray server", state: xray["ActiveState"] == "active" && xray["SubState"] == "running" && !xrayListener.isEmpty ? .passed : .warning,
                        detail: "systemd=\(xray["ActiveState"] ?? "unknown")/\(xray["SubState"] ?? "unknown"); listener=\(xrayListener.isEmpty ? "not observed" : xrayListener). Server readiness does not prove a client REALITY session."),
            NetworkProbe(id: "xhttp", title: "Xray XHTTP REALITY fallback", state: xhttpState,
                        detail: xhttpInstalled ? "systemd=\(xhttp["ActiveState"] ?? "unknown")/\(xhttp["SubState"] ?? "unknown"); listener=\(xhttpListener.isEmpty ? "not observed" : xhttpListener)" : "Secondary XHTTP transport is not configured"),
            NetworkProbe(id: "xhttp-tls", title: "XHTTP through Caddy TLS :443", state: xhttpTLSState,
                        detail: xhttpTLSInstalled ? "systemd=\(xhttpTLS["ActiveState"] ?? "unknown")/\(xhttpTLS["SubState"] ?? "unknown"); loopback=\(xhttpTLSListener.isEmpty ? "not observed" : xhttpTLSListener); Caddy route=\(xhttpTLSRoute ? "configured" : "not observed"); Caddy TLS=\(xhttpTLSCaddyReady ? "ready" : "not ready")" : "TLS-fronted XHTTP is not configured"),
            NetworkProbe(id: "caddy", title: "Caddy HTTPS container", state: caddy.hasPrefix("running|") ? .passed : .warning,
                        detail: caddy.isEmpty ? "Container ma-alice-https was not found" : "ma-alice-https state/restart policy: \(caddy)"),
            NetworkProbe(id: "resources", title: "VPS resource headroom", state: resourceState,
                        detail: resources.isEmpty ? "Resource metrics unavailable" : resources)
        ])
    }

    private static func firstLine(_ text: String?) -> String {
        text?.split(separator: "\n", omittingEmptySubsequences: true).first.map(String.init)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    private static func keyValues(_ text: String) -> [String: String] {
        Dictionary(uniqueKeysWithValues: text.split(whereSeparator: \.isWhitespace).compactMap { token in
            let pair = token.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard pair.count == 2 else { return nil }
            return (String(pair[0]), String(pair[1]))
        })
    }

    private static func httpsOK(_ text: String) -> Bool {
        guard let range = text.range(of: #"http=(\d{3})"#, options: .regularExpression),
              let code = Int(text[range].dropFirst(5)) else { return false }
        return (200..<400).contains(code) && (Double(value("tls", in: text)) ?? 0) > 0
    }

    private static func value(_ key: String, in text: String) -> String {
        text.split(separator: " ").first(where: { $0.hasPrefix("\(key)=") }).map { String($0.dropFirst(key.count + 1)) } ?? ""
    }
}
