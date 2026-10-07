import AppKit
import Foundation
import SwiftUI

@MainActor
final class HomeAccessController: ObservableObject {
  @Published private(set) var network: HomeNetwork?
  @Published private(set) var devices: [HomeDevice] = []
  @Published private(set) var snapshot = HomeNetworkSnapshot()
  @Published private(set) var lastDiscovery: Date?
  @Published private(set) var diagnostics = HomeDiscoveryDiagnostics()
  @Published private(set) var routerState: HomeRouterState = .notConfigured
  @Published private(set) var routerProviderName = "TP-Link Archer AX18"
  @Published private(set) var routerLastSync: Date?
  @Published private(set) var routerAddress =
    UserDefaults.standard.string(forKey: "home-router-address") ?? ""
  @Published private(set) var routerUsername =
    UserDefaults.standard.string(forKey: "home-router-username") ?? ""
  @Published private(set) var isRefreshing = false
  @Published private(set) var errorMessage: String?
  @Published private(set) var profiles: [LocalProfile] = []
  @Published private(set) var deviceProbes: [UUID: HomeDeviceProbeSnapshot] = [:]
  @Published private(set) var isProbingDevices = false

  @Published private(set) var gatewayAddress =
    UserDefaults.standard.string(forKey: "home-gateway-address") ?? "192.168.0.2"
  @Published private(set) var gatewayVPNAddress =
    UserDefaults.standard.string(forKey: "home-gateway-vpn-address") ?? "10.66.66.6"
  @Published private(set) var gatewayUsername =
    UserDefaults.standard.string(forKey: "home-gateway-username") ?? "root"
  @Published private(set) var gatewayKeyPath =
    UserDefaults.standard.string(forKey: "home-gateway-key-path") ?? ""
  @Published private(set) var gatewayStatus: HomeGatewayStatus = .unknown
  @Published private(set) var gatewayRouteStatus: HomeGatewayStatus = .unknown
  @Published private(set) var gatewaySSHStatus: HomeGatewayStatus = .unknown
  @Published private(set) var gatewayWireGuardStatus: HomeGatewayStatus = .unknown
  @Published private(set) var gatewayHandshakeAge: TimeInterval?

  @Published private(set) var homeActionMessage: String?
  private let store: InfrastructureStore?
  private let discovery: HomeDiscoveryService
  private let routerProvider: any RouterClientInventoryProvider
  private var refreshTask: Task<Void, Never>?
  init(
    store: InfrastructureStore? = try? InfrastructureStore(),
    discovery: HomeDiscoveryService = HomeDiscoveryService(),
    routerProvider: any RouterClientInventoryProvider = TPLinkArcherAX18Provider()
  ) {
    self.store = store
    self.discovery = discovery
    self.routerProvider = routerProvider
    profiles = ProfileStore.list(in: ProfileStore.homeAccessURL)
    Task { await load() }
  }
  func load() async {
    do {
      network = try await store?.activeHomeNetwork()
      devices = try await store?.homeDevices() ?? []
      profiles = ProfileStore.list(in: ProfileStore.homeAccessURL)

      await repairInventory()

      errorMessage = nil
    } catch {
      errorMessage = SecretRedactor.redact(error.localizedDescription)
    }
  }
  func saveNetwork(name: String, cidr: String, routerIP: String, notes: String) async {
    let now = Date()
    let value = HomeNetwork(
      id: network?.id ?? UUID(), name: name.trimmingCharacters(in: .whitespacesAndNewlines),
      cidr: cidr.trimmingCharacters(in: .whitespacesAndNewlines),
      routerIP: routerIP.trimmingCharacters(in: .whitespacesAndNewlines), notes: notes,
      createdAt: network?.createdAt ?? now, updatedAt: now)
    do {
      try await store?.save(homeNetwork: value)
      network = value
      errorMessage = nil
    } catch { errorMessage = SecretRedactor.redact(error.localizedDescription) }
  }
  func refresh() async {
    guard refreshTask == nil else { return }
    isRefreshing = true
    let configuration = network
    refreshTask = Task { [weak self, discovery, routerProvider] in
      guard let self else { return }
      var routerRecords: [HomeDiscoveryRecord] = []
      if !self.routerAddress.isEmpty,
        let password = KeychainService.load(account: "home-router-password"), !password.isEmpty
      {
        do {
          let clients: [RouterClientRecord]
          if self.routerState == .connected {
            do { clients = try await routerProvider.clients() } catch HomeRouterProviderError
              .authenticationRequired
            {
              _ = try await routerProvider.connect(
                address: self.routerAddress, username: self.routerUsername.nonEmptyValue,
                password: password)
              clients = try await routerProvider.clients()
            }
          } else {
            _ = try await routerProvider.connect(
              address: self.routerAddress, username: self.routerUsername.nonEmptyValue,
              password: password)
            clients = try await routerProvider.clients()
          }
          routerRecords = clients.flatMap { value in
            value.sources.map { source in
              HomeDiscoveryRecord(
                ip: value.ipv4 ?? value.ipv6 ?? "", mac: value.mac, hostname: value.hostname,
                source: source,
                evidence: value.online == true
                  ? "Connected in TP-Link router client table" : "Known to TP-Link router",
                routerDisplayName: value.displayName, connectionType: value.connectionType,
                online: source == .routerDHCP ? nil : value.online)
            }
          }
          if let routerIP = configuration?.routerIP.nonEmptyValue,
            !routerRecords.contains(where: { $0.ip == routerIP })
          {
            routerRecords.append(
              HomeDiscoveryRecord(
                ip: routerIP, mac: nil, hostname: nil, source: .routerClient,
                evidence: "Authenticated router inventory source", routerDisplayName: "Home Router",
                connectionType: .ethernet, online: true))
          }
          self.routerState = .connected
          self.routerLastSync = Date()
        } catch HomeRouterProviderError.authenticationRequired {
          await routerProvider.disconnect()
          self.routerState = .authenticationRequired
        } catch HomeRouterProviderError.authenticationFailed {
          self.routerState = .authenticationRequired
        } catch { self.routerState = .unavailable }
      } else if !self.routerAddress.isEmpty {
        self.routerState = .authenticationRequired
      } else {
        self.routerState = .notConfigured
      }
      do {
        let (resultSnapshot, records, resultDiagnostics) = try await discovery.discover(
          configuration: configuration, routerRecords: routerRecords)
        try Task.checkCancellation()
        await self.apply(snapshot: resultSnapshot, records: records, diagnostics: resultDiagnostics)
      } catch is CancellationError {} catch { self.present(error) }
    }
    await refreshTask?.value
    await repairInventory()
    refreshTask = nil
    isRefreshing = false
  }
  func stop() async {
    refreshTask?.cancel()
    refreshTask = nil
    isRefreshing = false
    await discovery.cancel()
  }
  private func apply(
    snapshot newSnapshot: HomeNetworkSnapshot, records: [HomeDiscoveryRecord],
    diagnostics newDiagnostics: HomeDiscoveryDiagnostics
  ) async {
    let now = Date()
    var updated = devices.map { device in
      var value = device
      value.status = HomePresence.status(
        lastSeen: value.lastSeen, now: now, homeMode: newSnapshot.mode)
      return value
    }
    var observedIDs = Set<UUID>()
    for record in records {
      let mac = HomeDeviceIdentity.normalizedMAC(record.mac)
      let id = HomeDeviceIdentity.stableID(mac: mac, ip: record.ip, hostname: record.hostname)
      let index =
        updated.firstIndex(where: {
          mac != nil && HomeDeviceIdentity.normalizedMAC($0.macAddress) == mac
        }) ?? updated.firstIndex(where: { $0.id == id })
      let device = HomeDeviceReconciler.merge(
        existing: index.map { updated[$0] }, record: record, now: now)
      let observedStatus: HomeDeviceReachability =
        record.online == true || record.source == .arp || record.source == .ndp ? .online : .unknown
      let observation = HomeDeviceObservation(
        deviceID: device.id, timestamp: now, status: observedStatus, evidence: record.evidence,
        ip: record.ip.nonEmptyValue, source: record.source)
      do { try await store?.save(homeDevice: device, observation: observation) } catch {
        errorMessage = SecretRedactor.redact(error.localizedDescription)
      }
      if let index { updated[index] = device } else { updated.append(device) }
      observedIDs.insert(device.id)
    }
    for device in updated where !observedIDs.contains(device.id) {
      try? await store?.save(homeDevice: device)
    }
    snapshot = newSnapshot
    diagnostics = newDiagnostics
    devices = updated.sorted {
      ($0.isPinned ? 0 : 1, $0.displayName.lowercased()) < (
        $1.isPinned ? 0 : 1, $1.displayName.lowercased()
      )
    }
    lastDiscovery = now
    errorMessage = nil
  }
  func saveRouterIntegration(address: String, username: String, password: String) async {
    let clean = address.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !clean.isEmpty else {
      errorMessage = "Router address is required."
      return
    }
    do {
      if !password.isEmpty { try KeychainService.save(password, account: "home-router-password") }
      UserDefaults.standard.set(clean, forKey: "home-router-address")
      UserDefaults.standard.set(username, forKey: "home-router-username")
      routerAddress = clean
      routerUsername = username
      await refresh()
    } catch { present(error) }
  }
  func testRouterConnection(address: String, username: String, password: String) async {
    do {
      let secret =
        password.isEmpty ? KeychainService.load(account: "home-router-password") ?? "" : password
      _ = try await routerProvider.connect(
        address: address, username: username.nonEmptyValue, password: secret)
      _ = try await routerProvider.clients()
      routerState = .connected
      errorMessage = nil
      await routerProvider.disconnect()
    } catch HomeRouterProviderError.authenticationRequired {
      routerState = .authenticationRequired
      errorMessage = "Router authentication is required."
    } catch HomeRouterProviderError.authenticationFailed {
      routerState = .authenticationRequired
      errorMessage = "Router authentication failed."
    } catch {
      routerState = .unavailable
      present(error)
    }
  }
  func forgetRouterCredentials() async {
    KeychainService.delete(account: "home-router-password")
    await routerProvider.disconnect()
    routerState = routerAddress.isEmpty ? .notConfigured : .authenticationRequired
  }
  func saveDevice(_ value: HomeDevice) async {
    var device = value
    device.nameIsManual = true
    device.typeIsManual = true
    device.discoverySources.insert(.manual)
    do {
      try await store?.save(homeDevice: device)
      await load()
    } catch { errorMessage = SecretRedactor.redact(error.localizedDescription) }
  }
  func addManual(
    name: String, type: HomeDeviceType, ip: String, mac: String, hostname: String, notes: String
  ) async {
    let normalized = HomeDeviceIdentity.normalizedMAC(mac)
    let now = Date()
    let id = HomeDeviceIdentity.stableID(
      mac: normalized, manualID: UUID(), ip: ip.nonEmptyValue, hostname: hostname.nonEmptyValue)
    let device = HomeDevice(
      id: id, displayName: name, hostname: hostname.nonEmptyValue,
      ipv4: ip.contains(":") ? nil : ip.nonEmptyValue, ipv6: ip.contains(":") ? ip : nil,
      macAddress: normalized, vendor: nil, type: type, customType: nil, status: .unknown,
      lastSeen: nil, firstSeen: now, discoverySources: [.manual], notes: notes.nonEmptyValue,
      nameIsManual: true, typeIsManual: true)
    await saveDevice(device)
  }
  func delete(_ id: UUID) async {
    do {
      try await store?.deleteHomeDevice(id)
      devices.removeAll { $0.id == id }
    } catch { errorMessage = SecretRedactor.redact(error.localizedDescription) }
  }
  func observations(for id: UUID) async -> [HomeDeviceObservation] {
    (try? await store?.homeObservations(deviceID: id, since: Date().addingTimeInterval(-2_592_000)))
      ?? []
  }
  func merge(source: UUID, into destination: UUID) async {
    guard let sourceDevice = devices.first(where: { $0.id == source }),
      var target = devices.first(where: { $0.id == destination })
    else { return }
    target.lastSeen = max(target.lastSeen ?? .distantPast, sourceDevice.lastSeen ?? .distantPast)
    target.firstSeen = min(target.firstSeen, sourceDevice.firstSeen)
    target.discoverySources.formUnion(sourceDevice.discoverySources)
    target.ipv4 = target.ipv4 ?? sourceDevice.ipv4
    target.ipv6 = target.ipv6 ?? sourceDevice.ipv6
    target.macAddress = target.macAddress ?? sourceDevice.macAddress
    do {
      try await store?.save(homeDevice: target)
      try await store?.mergeHomeDevices(source: source, destination: destination)
      await load()
    } catch { errorMessage = SecretRedactor.redact(error.localizedDescription) }
  }
  func importProfile(from url: URL) async {
    do {
      _ = try ProfileStore.importHomeAccess(from: url)
      profiles = ProfileStore.list(in: ProfileStore.homeAccessURL)
      errorMessage = nil
    } catch { errorMessage = SecretRedactor.redact(error.localizedDescription) }
  }
  func renameProfile(_ profile: LocalProfile, to name: String) {
    do {
      _ = try ProfileStore.rename(profile, name: name, in: ProfileStore.homeAccessURL)
      profiles = ProfileStore.list(in: ProfileStore.homeAccessURL)
    } catch { errorMessage = SecretRedactor.redact(error.localizedDescription) }
  }
  func deleteProfile(_ profile: LocalProfile) {
    do {
      try ProfileStore.delete(profile, within: ProfileStore.homeAccessURL)
      profiles = ProfileStore.list(in: ProfileStore.homeAccessURL)
    } catch { errorMessage = SecretRedactor.redact(error.localizedDescription) }
  }
  func saveGatewayIntegration(
    address: String,
    vpnAddress: String,
    username: String,
    keyPath: String
  ) {
    let address = address.trimmingCharacters(in: .whitespacesAndNewlines)
    let vpnAddress = vpnAddress.trimmingCharacters(in: .whitespacesAndNewlines)
    let username = username.trimmingCharacters(in: .whitespacesAndNewlines)
    let keyPath = keyPath.trimmingCharacters(in: .whitespacesAndNewlines)

    gatewayAddress = address.isEmpty ? "192.168.0.2" : address
    gatewayVPNAddress = vpnAddress.isEmpty ? "10.66.66.6" : vpnAddress
    gatewayUsername = username.isEmpty ? "root" : username
    gatewayKeyPath = keyPath

    UserDefaults.standard.set(gatewayAddress, forKey: "home-gateway-address")
    UserDefaults.standard.set(gatewayVPNAddress, forKey: "home-gateway-vpn-address")
    UserDefaults.standard.set(gatewayUsername, forKey: "home-gateway-username")
    UserDefaults.standard.set(gatewayKeyPath, forKey: "home-gateway-key-path")

    homeActionMessage = "Home Gateway settings saved."
  }

  func testGateway() async {
    gatewayStatus = .unknown
    gatewayRouteStatus = .unknown
    gatewaySSHStatus = .unknown
    gatewayWireGuardStatus = .unknown
    gatewayHandshakeAge = nil
    homeActionMessage = "Testing Home Gateway…"

    async let routeProbeTask = HomeDeviceProbeService.probe(ip: gatewayAddress)
    async let sshTask = HomeGatewayService.test(
      host: gatewayAddress,
      username: gatewayUsername,
      keyPath: gatewayKeyPath
    )

    let routeProbe = await routeProbeTask
    let sshResult = await sshTask

    gatewayRouteStatus = routeProbe.reachable ? .online : .offline
    gatewayStatus = gatewayRouteStatus
    gatewaySSHStatus = sshResult.status

    if sshResult.status == .online {
      if sshResult.message.contains("tdhome=up") {
        gatewayWireGuardStatus = .online
        gatewayHandshakeAge = parseGatewayHandshakeAge(sshResult.message)
      } else {
        gatewayWireGuardStatus = .offline
      }
    } else {
      gatewayWireGuardStatus = .unknown
    }

    var parts: [String] = []

    parts.append(
      "Route \(gatewayRouteStatus == .online ? "OK" : "failed")"
    )

    parts.append(
      "SSH \(gatewaySSHStatus == .online ? "OK" : "failed")"
    )

    switch gatewayWireGuardStatus {
    case .online:
      if let age = gatewayHandshakeAge {
        parts.append("WireGuard \(Int(age))s ago")
      } else {
        parts.append("WireGuard up")
      }
    case .offline:
      parts.append("WireGuard down")
    case .unknown:
      parts.append("WireGuard unknown")
    }

    homeActionMessage = parts.joined(separator: " · ")
  }

  func probeDevice(_ id: UUID) async {
    guard
      let device = devices.first(where: { $0.id == id }),
      let ip = usableAddress(for: device)
    else {
      homeActionMessage = "This device has no usable IP address."
      return
    }

    let result = await HomeDeviceProbeService.probe(ip: ip)

    deviceProbes[id] = result
    await applyProbeResult(result, deviceID: id, ip: ip)

    if result.reachable {
      let latency =
        result.latencyMilliseconds.map {
          String(format: "%.1f ms", $0)
        } ?? "ICMP unavailable"

      homeActionMessage =
        "\(device.displayName): \(latency) · \(result.serviceSummary)"
    } else {
      homeActionMessage =
        "\(device.displayName): no response from known probes."
    }
  }

  func probeAllDevices() async {
    guard !isProbingDevices else { return }

    isProbingDevices = true
    defer { isProbingDevices = false }

    let targets = devices.compactMap { device -> (UUID, String)? in
      guard let ip = usableAddress(for: device) else { return nil }
      return (device.id, ip)
    }

    let results = await withTaskGroup(
      of: (UUID, String, HomeDeviceProbeSnapshot).self,
      returning: [(UUID, String, HomeDeviceProbeSnapshot)].self
    ) { group in
      for (id, ip) in targets {
        group.addTask {
          (
            id,
            ip,
            await HomeDeviceProbeService.probe(ip: ip)
          )
        }
      }

      var values: [(UUID, String, HomeDeviceProbeSnapshot)] = []

      for await value in group {
        values.append(value)
      }

      return values
    }

    for (id, ip, result) in results {
      deviceProbes[id] = result
      await applyProbeResult(result, deviceID: id, ip: ip)
    }

    homeActionMessage =
      "Probed \(results.count) home devices."
  }

  func probe(for id: UUID) -> HomeDeviceProbeSnapshot? {
    deviceProbes[id]
  }

  func internetPolicy(for id: UUID) -> HomeInternetPolicy {
    let key = "home-device-internet-policy-\(id.uuidString)"
    guard
      let raw = UserDefaults.standard.string(forKey: key),
      let value = HomeInternetPolicy(rawValue: raw)
    else { return .unknown }
    return value
  }

  func setInternetPolicy(_ policy: HomeInternetPolicy, for id: UUID) {
    let key = "home-device-internet-policy-\(id.uuidString)"
    UserDefaults.standard.set(policy.rawValue, forKey: key)
  }

  func wakeDevice(_ id: UUID) async {
    guard let device = devices.first(where: { $0.id == id }) else { return }

    guard let mac = device.macAddress?.nonEmptyValue else {
      homeActionMessage = "\(device.displayName) has no MAC address for Wake-on-LAN."
      return
    }

    guard !gatewayKeyPath.isEmpty else {
      homeActionMessage = "Configure an SSH key for Home Gateway first."
      return
    }

    let result = await HomeGatewayService.wake(
      host: gatewayAddress,
      username: gatewayUsername,
      keyPath: gatewayKeyPath,
      mac: mac
    )

    if result.succeeded {
      homeActionMessage = "Wake-on-LAN packet sent to \(device.displayName)."
    } else {
      homeActionMessage =
        result.stderr.isEmpty
        ? "Wake-on-LAN failed."
        : result.stderr
    }
  }

  private func usableAddress(for device: HomeDevice) -> String? {
    guard
      let raw = (device.ipv4 ?? device.ipv6)?
        .trimmingCharacters(in: .whitespacesAndNewlines)
    else {
      return nil
    }

    guard
      !raw.isEmpty,
      raw != "0.0.0.0",
      raw != "::"
    else {
      return nil
    }

    return raw
  }

  private func applyProbeResult(
    _ result: HomeDeviceProbeSnapshot,
    deviceID: UUID,
    ip: String
  ) async {
    guard let index = devices.firstIndex(where: { $0.id == deviceID })
    else {
      return
    }

    let now = Date()
    var device = devices[index]

    if result.reachable {
      device.status = .online
      device.lastSeen = now
      device.lastSuccessfulObservation = now
      device.reachabilityEvidence =
        "Active Home Access probe confirmed reachability"
    } else {
      if snapshot.mode == .homeLAN {
        device.status = .offline
        device.reachabilityEvidence =
          "Active LAN probe received no response"
      } else {
        device.status = .unknown
        device.reachabilityEvidence =
          "Remote probe received no response; offline state not assumed"
      }
    }

    devices[index] = device

    let observation = HomeDeviceObservation(
      deviceID: device.id,
      timestamp: now,
      status: device.status,
      evidence: device.reachabilityEvidence ?? "Active probe",
      ip: ip,
      source: .probe
    )

    do {
      try await store?.save(
        homeDevice: device,
        observation: observation
      )
    } catch {
      errorMessage =
        SecretRedactor.redact(error.localizedDescription)
    }
  }

  private func inferredType(for device: HomeDevice) -> HomeDeviceType {
    let text = [
      device.displayName,
      device.hostname,
      device.routerDisplayName,
      device.vendor,
    ]
    .compactMap { $0 }
    .joined(separator: " ")
    .lowercased()

    if text.contains("macbook")
      || text == "mac"
      || text.hasPrefix("mac ")
    {
      return .mac
    }

    if text.contains("iphone")
      || text.contains("pixel")
      || text.contains("android")
      || text.contains("phone")
    {
      return .phone
    }

    if text.contains("matebook")
      || text.contains("huawei")
      || text.contains("laptop")
      || text.contains("notebook")
      || text.contains("windows")
    {
      return .computer
    }

    if text.contains("yandex")
      || text.contains("alice")
      || text.contains("alisa")
      || text.contains("station")
    {
      return .iot
    }

    if text.contains("openwrt")
      || text.contains("router")
      || text.contains("archer")
    {
      return .router
    }

    return .unknown
  }

  private func repairInventory() async {
    guard !devices.isEmpty else { return }

    var changed = false

    for index in devices.indices {
      var device = devices[index]
      var localChange = false

      if device.ipv4 == "0.0.0.0" {
        device.ipv4 = nil
        localChange = true
      }

      if device.ipv4 == gatewayAddress {
        if !device.nameIsManual
          && device.displayName != "TunnelDeck Gateway"
        {
          device.displayName = "TunnelDeck Gateway"
          localChange = true
        }

        if !device.typeIsManual && device.type != .router {
          device.type = .router
          localChange = true
        }

        if device.vendor == nil {
          device.vendor = "Xiaomi / OpenWrt"
          localChange = true
        }

        if device.preferredAccessURL == nil {
          device.preferredAccessURL =
            "http://\(gatewayAddress)"
          localChange = true
        }

        if device.preferredSSHHost == nil {
          device.preferredSSHHost = gatewayAddress
          localChange = true
        }
      } else if !device.typeIsManual && device.type == .unknown {
        let inferred = inferredType(for: device)

        if inferred != .unknown {
          device.type = inferred
          localChange = true
        }
      }

      if localChange {
        devices[index] = device
        changed = true

        try? await store?.save(homeDevice: device)
      }
    }

    // If an old OpenWrt identity has the same MAC as the real
    // 192.168.0.2 gateway, merge it into the canonical identity.
    if let gatewayIndex = devices.firstIndex(where: {
      $0.ipv4 == gatewayAddress
    }),
      let gatewayMAC = HomeDeviceIdentity.normalizedMAC(
        devices[gatewayIndex].macAddress
      )
    {
      let gatewayID = devices[gatewayIndex].id

      let duplicateIDs = devices.compactMap { device -> UUID? in
        guard device.id != gatewayID else { return nil }

        return HomeDeviceIdentity.normalizedMAC(
          device.macAddress
        ) == gatewayMAC
          ? device.id
          : nil
      }

      if !duplicateIDs.isEmpty {
        var target = devices[gatewayIndex]

        for sourceID in duplicateIDs {
          guard
            let source = devices.first(where: {
              $0.id == sourceID
            })
          else {
            continue
          }

          target.lastSeen = max(
            target.lastSeen ?? .distantPast,
            source.lastSeen ?? .distantPast
          )

          target.firstSeen = min(
            target.firstSeen,
            source.firstSeen
          )

          target.discoverySources.formUnion(
            source.discoverySources
          )

          target.ipv6 = target.ipv6 ?? source.ipv6
          target.hostname = target.hostname ?? source.hostname
          target.notes = target.notes ?? source.notes

          try? await store?.save(homeDevice: target)
          try? await store?.mergeHomeDevices(
            source: sourceID,
            destination: gatewayID
          )
        }

        devices = (try? await store?.homeDevices()) ?? devices
        changed = true
      }
    }

    if changed {
      devices.sort {
        (
          $0.isPinned ? 0 : 1,
          $0.displayName.lowercased()
        ) < (
          $1.isPinned ? 0 : 1,
          $1.displayName.lowercased()
        )
      }
    }
  }

  private func parseGatewayHandshakeAge(
    _ message: String
  ) -> TimeInterval? {
    let now = Date().timeIntervalSince1970

    for line in message.split(separator: "\n").reversed() {
      let parts = line.split(whereSeparator: \.isWhitespace)

      guard
        let raw = parts.last,
        let epoch = Double(raw),
        epoch > 0
      else {
        continue
      }

      return max(0, now - epoch)
    }

    return nil
  }

  private func present(_ error: Error) {
    errorMessage = SecretRedactor.redact(error.localizedDescription)
  }
}

extension String {
  fileprivate var nonEmptyValue: String? {
    let value = trimmingCharacters(in: .whitespacesAndNewlines)
    return value.isEmpty ? nil : value
  }
}
