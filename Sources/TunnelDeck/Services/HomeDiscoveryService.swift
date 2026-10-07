import Foundation
@preconcurrency import Network

enum HomeDiscoveryParser {
  static func arp(_ text: String) -> [HomeDiscoveryRecord] {
    text.split(separator: "\n").compactMap { line in
      let value = String(line)
      guard let ip = value.firstMatch(of: /\(([0-9.]+)\)/)?.1 else { return nil }
      let fields = value.split(whereSeparator: \.isWhitespace)
      guard let at = fields.firstIndex(of: "at"), fields.indices.contains(at + 1) else {
        return nil
      }
      let raw = String(fields[at + 1])
      guard raw != "(incomplete)", let mac = HomeDeviceIdentity.normalizedMAC(raw) else {
        return nil
      }
      let host = fields.first.map(String.init).flatMap { $0 == "?" ? nil : $0 }
      return HomeDiscoveryRecord(
        ip: String(ip), mac: mac, hostname: host, source: .arp, evidence: "Fresh ARP neighbour")
    }
  }
  static func ndp(_ text: String) -> [HomeDiscoveryRecord] {
    text.split(separator: "\n").compactMap { line in
      let fields = line.split(whereSeparator: \.isWhitespace)
      guard fields.count >= 3 else { return nil }
      let ip = String(fields[0]).split(separator: "%").first.map(String.init) ?? ""
      guard ip.contains(":"), !ip.lowercased().contains("neighbor") else { return nil }
      let mac = HomeDeviceIdentity.normalizedMAC(String(fields[1]))
      guard mac != nil else { return nil }
      return HomeDiscoveryRecord(
        ip: ip, mac: mac, hostname: nil, source: .ndp, evidence: "Fresh IPv6 neighbour")
    }
  }
  static func route(_ text: String) -> (gateway: String?, interface: String?) {
    var gateway: String?
    var interface: String?
    for line in text.split(separator: "\n") {
      let pair = line.split(separator: ":", maxSplits: 1).map {
        String($0).trimmingCharacters(in: .whitespaces)
      }
      guard pair.count == 2 else { continue }
      if pair[0] == "gateway" { gateway = pair[1] }
      if pair[0] == "interface" { interface = pair[1] }
    }
    return (gateway, interface)
  }
}

actor LocalCommandRunner {
  private var process: Process?
  func run(_ executable: String, _ arguments: [String]) async throws -> String {
    guard process == nil else { throw CancellationError() }
    let task = Process()
    let pipe = Pipe()
    task.executableURL = URL(fileURLWithPath: executable)
    task.arguments = arguments
    task.standardOutput = pipe
    task.standardError = Pipe()
    process = task
    defer {
      if process === task { process = nil }
      try? pipe.fileHandleForReading.close()
    }
    return try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { continuation in
        task.terminationHandler = { finished in
          let data = pipe.fileHandleForReading.readDataToEndOfFile()
          finished.terminationHandler = nil
          continuation.resume(
            returning: finished.terminationStatus == 0 ? String(decoding: data, as: UTF8.self) : "")
        }
        do { try task.run() } catch {
          task.terminationHandler = nil
          continuation.resume(throwing: error)
        }
      }
    } onCancel: {
      Task { await self.cancel() }
    }
  }
  func cancel() { if let process, process.isRunning { process.terminate() } }
  func activeProcessCount() -> Int { process == nil ? 0 : 1 }
}

actor HomeDiscoveryService {
  private let runner: LocalCommandRunner
  private let warmer: any HomeNeighborWarming
  init(
    runner: LocalCommandRunner = LocalCommandRunner(),
    warmer: any HomeNeighborWarming = NetworkNeighborWarmer()
  ) {
    self.runner = runner
    self.warmer = warmer
  }
  func discover(configuration: HomeNetwork?, routerRecords: [HomeDiscoveryRecord] = []) async throws
    -> (HomeNetworkSnapshot, [HomeDiscoveryRecord], HomeDiscoveryDiagnostics)
  {
    let started = Date()
    let arpText = (try? await runner.run("/usr/sbin/arp", ["-an"])) ?? ""
    let initialARP = HomeDiscoveryParser.arp(arpText)
    try Task.checkCancellation()
    let ndpText = (try? await runner.run("/usr/sbin/ndp", ["-an"])) ?? ""
    let defaultRoute = (try? await runner.run("/sbin/route", ["-n", "get", "default"])) ?? ""
    let route = HomeDiscoveryParser.route(defaultRoute)
    let localValue = LocalNetworkService.lanIPv4()
    let lanIP = (localValue.isEmpty || localValue == "—") ? nil : localValue
    var snapshot = HomeNetworkSnapshot(
      macLANIP: lanIP, probableSubnet: lanIP.flatMap(Self.suggestedCIDR),
      defaultGateway: route.gateway, interface: route.interface)
    if let configuration, !configuration.cidr.isEmpty {
      if let lanIP, Self.contains(configuration.cidr, ip: lanIP) {
        snapshot.mode = .homeLAN
        snapshot.routeEvidence = "Local address belongs to configured Home LAN"
      } else if !configuration.routerIP.isEmpty {
        let target =
          (try? await runner.run("/sbin/route", ["-n", "get", configuration.routerIP])) ?? ""
        let path = HomeDiscoveryParser.route(target)
        if let interface = path.interface, interface.hasPrefix("utun") {
          snapshot.mode = .remote
          snapshot.routeEvidence = "Verified route through \(interface)"
        } else if lanIP != nil {
          snapshot.mode = .other
          snapshot.routeEvidence = "No verified route to configured Home LAN"
        }
      }
      if configuration.routerIP == lanIP, route.gateway != lanIP {
        snapshot.routerConfigurationWarning =
          "Configured router address appears to be this Mac, not the gateway."
      }
    } else if lanIP != nil {
      snapshot.mode = .other
      snapshot.routeEvidence = "Configure and confirm the Home LAN CIDR"
    }
    var diagnostics = HomeDiscoveryDiagnostics(
      mode: routerRecords.isEmpty ? "Passive" : "Router + Passive", initialARP: initialARP.count,
      ndp: HomeDiscoveryParser.ndp(ndpText).count, routerRecords: routerRecords.count)
    var finalARP = initialARP
    if snapshot.mode == .homeLAN, let configuration, !configuration.cidr.isEmpty {
      let candidates = Self.ipv4Candidates(
        cidr: configuration.cidr, excluding: lanIP, maxHosts: 512)
      diagnostics.candidates = candidates.count
      if !candidates.isEmpty {
        diagnostics.mode = routerRecords.isEmpty ? "Active" : "Router + Active"
        try await warmer.warm(candidates)
        try Task.checkCancellation()
        try? await Task.sleep(for: .milliseconds(180))
        let second = (try? await runner.run("/usr/sbin/arp", ["-an"])) ?? ""
        finalARP = HomeDiscoveryParser.arp(second)
      } else if Self.hostCount(cidr: configuration.cidr) > 512 {
        diagnostics.message = "Subnet too large for active neighbour discovery"
      }
    }
    diagnostics.finalARP = finalARP.count
    if diagnostics.finalARP == 0 && routerRecords.isEmpty {
      diagnostics.message =
        diagnostics.message ?? "No neighbour entries were discovered after active LAN scan"
    }
    var all = routerRecords + finalARP + HomeDiscoveryParser.ndp(ndpText)
    if let gateway = snapshot.defaultGateway, !all.contains(where: { $0.ip == gateway }) {
      all.append(
        HomeDiscoveryRecord(
          ip: gateway, mac: nil, hostname: nil, source: .routerClient,
          evidence: "Detected default gateway", routerDisplayName: "Home Router",
          connectionType: .ethernet, online: nil))
    }
    let records = all.filter { record in
      guard
        record.ip != lanIP,
        record.ip != "0.0.0.0",
        record.ip != "::",
        !record.ip.isEmpty,
        record.mac != "ff:ff:ff:ff:ff:ff"
      else { return false }
      if let first = Int(record.ip.split(separator: ".").first ?? ""), (224...239).contains(first) {
        return false
      }
      return true
    }
    diagnostics.reconciled =
      Set(
        records.map { HomeDeviceIdentity.stableID(mac: $0.mac, ip: $0.ip, hostname: $0.hostname) }
      ).count
    diagnostics.duration = Date().timeIntervalSince(started)
    return (snapshot, records, diagnostics)
  }
  func cancel() async { await runner.cancel() }
  func activeProcessCount() async -> Int { await runner.activeProcessCount() }
  static func suggestedCIDR(_ ip: String) -> String? {
    let parts = ip.split(separator: ".")
    guard parts.count == 4, parts.allSatisfy({ UInt8($0) != nil }) else { return nil }
    return parts.prefix(3).joined(separator: ".") + ".0/24"
  }
  static func contains(_ cidr: String, ip: String) -> Bool {
    let parts = cidr.split(separator: "/")
    let address = ip.split(separator: ".").compactMap { UInt32($0) }
    guard parts.count == 2, let bits = Int(parts[1]), bits >= 0, bits <= 32, address.count == 4
    else { return false }
    let network = parts[0].split(separator: ".").compactMap { UInt32($0) }
    guard network.count == 4 else { return false }
    func value(_ p: [UInt32]) -> UInt32 { p.reduce(0) { ($0 << 8) | $1 } }
    let mask: UInt32 = bits == 0 ? 0 : UInt32.max << UInt32(32 - bits)
    return value(address) & mask == value(network) & mask
  }
  static func hostCount(cidr: String) -> Int {
    guard let prefix = Int(cidr.split(separator: "/").last ?? ""), prefix >= 0, prefix <= 32 else {
      return 0
    }
    let bits = 32 - prefix
    return bits >= 31 ? Int.max : max(0, (1 << bits) - 2)
  }
  static func ipv4Candidates(cidr: String, excluding ownIP: String?, maxHosts: Int) -> [String] {
    let pieces = cidr.split(separator: "/")
    let octets = pieces.first?.split(separator: ".").compactMap { UInt32($0) } ?? []
    guard pieces.count == 2, octets.count == 4, let prefix = Int(pieces[1]), prefix >= 0,
      prefix <= 32
    else { return [] }
    let count = hostCount(cidr: cidr)
    guard count > 0, count <= maxHosts else { return [] }
    let raw = octets.reduce(0) { ($0 << 8) | $1 }
    let mask: UInt32 = prefix == 0 ? 0 : UInt32.max << UInt32(32 - prefix)
    let network = raw & mask
    return (1...count).compactMap { offset in
      let value = network + UInt32(offset)
      let ip = "\((value>>24)&255).\((value>>16)&255).\((value>>8)&255).\(value&255)"
      return ip == ownIP ? nil : ip
    }
  }
}

protocol HomeNeighborWarming: Sendable { func warm(_ addresses: [String]) async throws }
actor NetworkNeighborWarmer: HomeNeighborWarming {
  private let concurrency: Int
  init(concurrency: Int = 12) { self.concurrency = max(1, min(16, concurrency)) }
  func warm(_ addresses: [String]) async throws {
    var index = 0
    while index < addresses.count {
      try Task.checkCancellation()
      let end = min(index + concurrency, addresses.count)
      let batch = Array(addresses[index..<end])
      await withTaskGroup(of: Void.self) { group in
        for address in batch { group.addTask { await Self.probe(address) } }
      }
      index = end
    }
  }
  private static func probe(_ address: String) async {
    let connection = NWConnection(host: NWEndpoint.Host(address), port: 9, using: .udp)
    let queue = DispatchQueue(label: "TunnelDeck.HomeDiscovery.UDP")
    connection.start(queue: queue)
    await withCheckedContinuation { continuation in
      connection.send(
        content: Data([0]),
        completion: .contentProcessed { _ in
          connection.cancel()
          continuation.resume()
        })
    }
  }
}
