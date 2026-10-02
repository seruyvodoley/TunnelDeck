import Foundation

enum BaselineEngine {
    static func capture(nodeID: UUID, endpoints: [NetworkEndpoint], units: [UnitStatus], wireGuard: WireGuardSnapshot, ssh: SSHSecuritySnapshot, hashes: [String: String], now: Date = Date()) -> ConfigurationBaseline { ConfigurationBaseline(id: UUID(), nodeID: nodeID, createdAt: now, publicListeners: endpoints.filter { $0.classification == .publicInternet }.map { "\($0.protocolName.rawValue):\($0.port)" }.sorted(), services: units.map(\.name).sorted(), ports: Array(Set(endpoints.map(\.port))).sorted(), wireGuardInterfaces: wireGuard.state == .unknown ? [] : [wireGuard.interface], peerPublicIdentifiers: wireGuard.peers.map(\.publicKey).sorted(), dnsBinds: endpoints.filter { $0.port == 53 }.flatMap(\.bindAddresses).sorted(), sshPolicy: ["port":ssh.port,"passwordAuthentication":ssh.passwordAuthentication,"keyboardInteractiveAuthentication":ssh.keyboardInteractiveAuthentication,"pubkeyAuthentication":ssh.pubkeyAuthentication,"permitRootLogin":ssh.permitRootLogin], configurationHashes: hashes) }
    static func diff(baseline: ConfigurationBaseline, current: ConfigurationBaseline, at: Date = Date()) -> [ConfigurationDrift] {
        var result: [ConfigurationDrift] = []
        func item(_ kind: DriftChangeKind, _ category: String, _ key: String, _ old: String?, _ new: String?) -> ConfigurationDrift { ConfigurationDrift(id: UUID(), nodeID: baseline.nodeID, baselineID: baseline.id, detectedAt: at, kind: kind, category: category, key: key, previousValue: old, currentValue: new) }
        func compare(_ old: [String], _ new: [String], _ category: String) { for key in Set(new).subtracting(old).sorted() { result.append(item(.added,category,key,nil,key)) }; for key in Set(old).subtracting(new).sorted() { result.append(item(.removed,category,key,key,nil)) } }
        compare(baseline.publicListeners,current.publicListeners,"public-listener"); compare(baseline.services,current.services,"service"); compare(baseline.peerPublicIdentifiers,current.peerPublicIdentifiers,"wireguard-peer"); compare(baseline.dnsBinds,current.dnsBinds,"dns-bind")
        for key in Set(baseline.sshPolicy.keys).union(current.sshPolicy.keys).sorted() where baseline.sshPolicy[key] != current.sshPolicy[key] { result.append(item(.changed,"ssh-policy",key,baseline.sshPolicy[key],current.sshPolicy[key])) }
        for key in Set(baseline.configurationHashes.keys).union(current.configurationHashes.keys).sorted() where baseline.configurationHashes[key] != current.configurationHashes[key] { result.append(item(.changed,"config-hash",key,baseline.configurationHashes[key],current.configurationHashes[key])) }
        return result
    }
}
