import Foundation

enum ExposureAnalyzer {
    static func analyze(listeners: [Listener], nodeID: UUID, publicAddresses: Set<String>, vpnAddresses: Set<String>, firewallEvidence: String, serviceNames: [Int: String] = [:], observedAt: Date = Date()) -> [NetworkEndpoint] {
        let groups = Dictionary(grouping: listeners) { "\(normalizedProtocol($0.protocolName))|\($0.port)|\(logicalService($0, serviceNames))" }
        return groups.values.compactMap { group in
            guard let sample = group.first else { return nil }
            let addresses = Array(Set(group.map { normalizeAddress($0.address) })).sorted()
            let classification = classify(addresses: addresses, port: sample.port, protocolName: normalizedProtocol(sample.protocolName), publicAddresses: publicAddresses, vpnAddresses: vpnAddresses, firewallEvidence: firewallEvidence)
            return NetworkEndpoint(id: stableID(nodeID: nodeID, key: "\(normalizedProtocol(sample.protocolName))|\(sample.port)|\(logicalService(sample, serviceNames))"), nodeID: nodeID, serviceID: nil, protocolName: TransportProtocol(rawValue: normalizedProtocol(sample.protocolName)) ?? .unknown, port: sample.port, bindAddresses: addresses, addressFamily: family(addresses), firewallEvidence: relevantFirewallLines(firewallEvidence, port: sample.port), classification: classification.0, explanation: classification.1, observedAt: observedAt)
        }.sorted { $0.port == $1.port ? $0.explanation < $1.explanation : $0.port < $1.port }
    }

    static func displayName(_ endpoint: NetworkEndpoint, listeners: [Listener], serviceNames: [Int: String] = [:]) -> String { serviceNames[endpoint.port] ?? listeners.first(where: { $0.port == endpoint.port }).map { logicalService($0, serviceNames) } ?? "Unknown listener" }

    private static func classify(addresses: [String], port: Int, protocolName: String, publicAddresses: Set<String>, vpnAddresses: Set<String>, firewallEvidence: String) -> (ExposureClassification, String) {
        if addresses.allSatisfy({ $0 == "127.0.0.1" || $0 == "::1" }) { return (.loopback, "Bound only to loopback") }
        if addresses.allSatisfy({ vpnAddresses.contains($0) }) { return (.vpnOnly, "All bind addresses belong to discovered VPN interfaces") }
        if addresses.allSatisfy(isPrivate) { return (.privateLAN, "All bind addresses are private; route reachability is not asserted") }
        let evidence = relevantFirewallLines(firewallEvidence, port: port).joined(separator: " ").lowercased()
        if evidence.contains("deny") || evidence.contains("reject") || evidence.contains("drop") { return (.firewallBlocked, "Firewall evidence blocks this port") }
        let wildcard = addresses.contains("0.0.0.0") || addresses.contains("::") || addresses.contains("*")
        let explicitPublicBind = addresses.contains { publicAddresses.contains($0) }
        let explicitlyAllowed = evidence.contains("allow") || evidence.contains("accept")
        if (wildcard || explicitPublicBind) && explicitlyAllowed { return (.publicInternet, "Public/wildcard bind and firewall allow evidence were both observed") }
        if wildcard { return (.unknown, "Wildcard bind alone does not prove internet reachability; firewall evidence is insufficient") }
        if explicitPublicBind { return (.unknown, "Public-address bind observed, but firewall/routing reachability is unproven") }
        return (.unknown, "Available bind and firewall evidence is insufficient")
    }
    private static func relevantFirewallLines(_ text: String, port: Int) -> [String] { text.split(separator: "\n").map(String.init).filter { $0.range(of: "(^|[^0-9])\(port)(/|[^0-9]|$)", options: .regularExpression) != nil } }
    private static func normalizedProtocol(_ value: String) -> String { value.lowercased().hasPrefix("tcp") ? "tcp" : value.lowercased().hasPrefix("udp") ? "udp" : "unknown" }
    private static func normalizeAddress(_ value: String) -> String { value.trimmingCharacters(in: CharacterSet(charactersIn: "[]")) }
    private static func family(_ addresses: [String]) -> AddressFamily { let v4 = addresses.contains { !$0.contains(":") }; let v6 = addresses.contains { $0.contains(":") }; return v4 && v6 ? .dualStack : v6 ? .ipv6 : v4 ? .ipv4 : .unknown }
    private static func isPrivate(_ address: String) -> Bool { let octets = address.split(separator: "."); let private172 = octets.count == 4 && octets[0] == "172" && (16...31).contains(Int(octets[1]) ?? -1); return address.hasPrefix("10.") || address.hasPrefix("192.168.") || private172 || address.lowercased().hasPrefix("fc") || address.lowercased().hasPrefix("fd") }
    private static func logicalService(_ listener: Listener, _ names: [Int: String]) -> String { if let name = names[listener.port] { return name }; let process = listener.process.lowercased(); if process.contains("sshd") || listener.port == 22 { return "SSH" }; if process.contains("adguardhome") { return listener.port == 53 ? "AdGuard DNS" : "AdGuard Web" }; if process.contains("openvpn") { return "OpenVPN" }; return process.isEmpty ? "Unknown listener" : listener.process }
    private static func stableID(nodeID: UUID, key: String) -> UUID { var bytes = [UInt8](repeating: 0, count: 16); for (index, byte) in (nodeID.uuidString + key).utf8.enumerated() { bytes[index % 16] = bytes[index % 16] &* 31 &+ byte }; return UUID(uuid: (bytes[0],bytes[1],bytes[2],bytes[3],bytes[4],bytes[5],bytes[6],bytes[7],bytes[8],bytes[9],bytes[10],bytes[11],bytes[12],bytes[13],bytes[14],bytes[15])) }
}
