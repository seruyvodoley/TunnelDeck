import AppKit
import SwiftUI

struct HomeAccessView: View {
  @EnvironmentObject var model: AppViewModel

  var body: some View {
    HomeAccessContentView(
      home: model.home,
      defaultGatewayKeyPath: model.settings.keyPath
    )
  }
}

private struct HomeAccessContentView: View {
  @ObservedObject var home: HomeAccessController
  let defaultGatewayKeyPath: String

  @StateObject private var state = HomeAccessScreenState()

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 18) {
        summary
        gatewayIntegration
        configuration
        routerIntegration
        devices
        profiles
      }
      .padding(20)
    }
    .task {
      await home.load()
      state.reflect(home.network)
      state.reflectRouter(home)
      state.reflectGateway(home, fallbackKeyPath: defaultGatewayKeyPath)

      await home.refresh()

      while !Task.isCancelled {
        try? await Task.sleep(for: .seconds(60))
        guard !Task.isCancelled else { break }
        await home.refresh()
      }
    }
    .onDisappear {
      Task { await home.stop() }
    }
    .sheet(item: $state.editingDevice) { device in
      HomeDeviceEditor(
        device: device,
        loadHistory: { await home.observations(for: device.id) },
        refresh: { await home.refresh() }
      ) { updated in
        Task { await home.saveDevice(updated) }
      }
    }
    .sheet(isPresented: $state.addingDevice) {
      ManualHomeDeviceSheet { value in
        Task {
          await home.addManual(
            name: value.name,
            type: value.type,
            ip: value.ip,
            mac: value.mac,
            hostname: value.hostname,
            notes: value.notes
          )
        }
      }
    }
    .sheet(isPresented: $state.qrVisible) {
      if let image = state.qrImage {
        VStack(spacing: 16) {
          Text(state.qrName).font(.title2.bold())
          Image(nsImage: image)
            .interpolation(.none)
            .resizable()
            .frame(width: 360, height: 360)
          Label(
            "This QR contains private WireGuard configuration.",
            systemImage: "exclamationmark.triangle.fill"
          )
          .foregroundStyle(.red)
        }
        .padding(24)
      }
    }
    .confirmationDialog(
      "Delete this device and its local observation history?",
      isPresented: $state.confirmDeviceDelete
    ) {
      Button("Delete", role: .destructive) {
        if let id = state.pendingDeviceDelete {
          Task { await home.delete(id) }
        }
      }
      Button("Cancel", role: .cancel) {}
    }
    .confirmationDialog(
      "Delete this local Home Access profile?",
      isPresented: $state.confirmProfileDelete
    ) {
      Button("Delete", role: .destructive) {
        if let profile = state.pendingProfileDelete {
          home.deleteProfile(profile)
        }
      }
      Button("Cancel", role: .cancel) {}
    }
  }

  private var summary: some View {
    MetricCard(title: "Home status", icon: "house.and.flag.fill") {
      VStack(spacing: 10) {
        HStack {
          StatusDot(state: stateForMode(home.snapshot.mode))
          Text(home.snapshot.mode.rawValue)
            .font(.title3.bold())

          Spacer()

          Button {
            Task { await home.refresh() }
          } label: {
            Label(
              home.isRefreshing ? "Refreshing…" : "Refresh",
              systemImage: "arrow.clockwise"
            )
          }
          .disabled(home.isRefreshing)
        }

        HStack {
          metric(
            "Seen now",
            home.devices.filter { $0.status == .online }.count
          )
          metric("Known", home.devices.count)
          metric(
            "Pinned",
            home.devices.filter(\.isPinned).count
          )
        }

        KeyValueRow(
          key: "Router",
          value: "\(home.routerProviderName) · \(home.routerState.rawValue)"
        )

        KeyValueRow(
          key: "Home Gateway",
          value:
            "\(home.gatewayAddress) · \(home.gatewayVPNAddress) · \(home.gatewayStatus.rawValue)"
        )

        KeyValueRow(key: "Path", value: pathText)
        KeyValueRow(
          key: "Mac LAN",
          value: home.snapshot.macLANIP ?? "Unavailable"
        )
        KeyValueRow(
          key: "Interface",
          value: home.snapshot.interface ?? "Unknown"
        )
        KeyValueRow(
          key: "Gateway",
          value: home.snapshot.defaultGateway ?? "Unknown"
        )
        KeyValueRow(
          key: "Last discovery",
          value: home.lastDiscovery?.formatted(
            .relative(presentation: .numeric)
          ) ?? "Never"
        )

        KeyValueRow(
          key: "Discovery",
          value:
            "\(home.diagnostics.mode) · router \(home.diagnostics.routerRecords), ARP \(home.diagnostics.initialARP)→\(home.diagnostics.finalARP), NDP \(home.diagnostics.ndp), devices \(home.diagnostics.reconciled), \(home.diagnostics.duration.formatted(.number.precision(.fractionLength(1)))) s"
        )

        if let warning = home.snapshot.routerConfigurationWarning {
          Text(warning).foregroundStyle(.orange)
        }

        if let error = home.errorMessage {
          Text(error).foregroundStyle(.orange)
        }

        if let message = home.homeActionMessage {
          Text(message)
            .font(.caption)
            .foregroundStyle(.secondary)
            .textSelection(.enabled)
        }
      }
    }
  }

  private var gatewayIntegration: some View {
    MetricCard(
      title: "Home Gateway · Xiaomi/OpenWrt",
      icon: "point.3.connected.trianglepath.dotted"
    ) {
      VStack(alignment: .leading, spacing: 12) {
        HStack {
          StatusDot(state: gatewayHealth)

          VStack(alignment: .leading, spacing: 2) {
            Text("TunnelDeck Home Gateway")
              .font(.headline)

            Text(
              "Remote VPN → VPS → Xiaomi/OpenWrt → Home LAN"
            )
            .font(.caption)
            .foregroundStyle(.secondary)
          }

          Spacer()

          Text(home.gatewayStatus.rawValue)
            .foregroundStyle(.secondary)
        }

        GroupBox("Gateway health") {
          VStack(spacing: 7) {
            gatewayStatusRow(
              title: "Home route",
              detail: home.gatewayAddress,
              status: home.gatewayRouteStatus
            )

            gatewayStatusRow(
              title: "SSH",
              detail: "\(home.gatewayUsername)@\(home.gatewayAddress)",
              status: home.gatewaySSHStatus
            )

            gatewayStatusRow(
              title: "WireGuard tdhome",
              detail: gatewayHandshakeText,
              status: home.gatewayWireGuardStatus
            )
          }
          .padding(6)
        }

        Grid(
          alignment: .leading,
          horizontalSpacing: 12,
          verticalSpacing: 8
        ) {
          GridRow {
            Text("LAN address")
              .foregroundStyle(.secondary)

            TextField(
              "192.168.0.2",
              text: $state.gatewayAddress
            )
          }

          GridRow {
            Text("WireGuard")
              .foregroundStyle(.secondary)

            TextField(
              "10.66.66.6",
              text: $state.gatewayVPNAddress
            )
          }

          GridRow {
            Text("SSH user")
              .foregroundStyle(.secondary)

            TextField(
              "root",
              text: $state.gatewayUsername
            )
          }

          GridRow {
            Text("SSH key")
              .foregroundStyle(.secondary)

            TextField(
              "/Users/.../.ssh/key",
              text: $state.gatewayKeyPath
            )
          }
        }

        HStack {
          Button("Save Gateway") {
            home.saveGatewayIntegration(
              address: state.gatewayAddress,
              vpnAddress: state.gatewayVPNAddress,
              username: state.gatewayUsername,
              keyPath: state.gatewayKeyPath
            )
          }

          Button("Save & Test All") {
            home.saveGatewayIntegration(
              address: state.gatewayAddress,
              vpnAddress: state.gatewayVPNAddress,
              username: state.gatewayUsername,
              keyPath: state.gatewayKeyPath
            )

            Task {
              await home.testGateway()
            }
          }
          .buttonStyle(.borderedProminent)

          Button("Open LuCI") {
            openURL(
              "http://\(state.gatewayAddress)"
            )
          }

          Spacer()
        }

        Text(
          "Overall gateway state follows actual Home LAN reachability. SSH and WireGuard are shown separately so an SSH authentication problem no longer makes the whole home route appear offline."
        )
        .font(.caption)
        .foregroundStyle(.secondary)

        Text(
          "The Xiaomi is the private return path into 192.168.0.0/24. It is not used as the normal Internet VPN router."
        )
        .font(.caption)
        .foregroundStyle(.secondary)
      }
    }
  }

  private var gatewayHandshakeText: String {
    guard let age = home.gatewayHandshakeAge else {
      return home.gatewayVPNAddress
    }

    if age < 60 {
      return "\(home.gatewayVPNAddress) · \(Int(age))s ago"
    }

    let minutes = Int(age / 60)
    return "\(home.gatewayVPNAddress) · \(minutes)m ago"
  }

  private func gatewayStatusRow(
    title: String,
    detail: String,
    status: HomeGatewayStatus
  ) -> some View {
    HStack {
      StatusDot(
        state: {
          switch status {
          case .online:
            return .online
          case .offline:
            return .offline
          case .unknown:
            return .unknown
          }
        }()
      )

      Text(title)
        .frame(width: 130, alignment: .leading)

      Text(detail)
        .foregroundStyle(.secondary)
        .textSelection(.enabled)

      Spacer()

      Text(status.rawValue)
        .foregroundStyle(.secondary)
    }
  }

  private var configuration: some View {
    MetricCard(title: "Home Network Configuration", icon: "network") {
      VStack(alignment: .leading, spacing: 10) {
        TextField(
          "Home Network Name",
          text: $state.networkName
        )
        TextField(
          "Home LAN CIDR",
          text: $state.cidr
        )
        TextField(
          "Router IP",
          text: $state.routerIP
        )
        TextField(
          "Optional notes",
          text: $state.networkNotes
        )

        HStack {
          if let suggestion = home.snapshot.probableSubnet,
            state.cidr.isEmpty
          {
            Button("Use discovered \(suggestion)") {
              state.cidr = suggestion
              if let gateway = home.snapshot.defaultGateway {
                state.routerIP = gateway
              }
            }
          }

          if let gateway = home.snapshot.defaultGateway,
            state.routerIP != gateway
          {
            Button("Use detected gateway \(gateway)") {
              state.routerIP = gateway
            }
          }

          Spacer()

          Button("Save Home Network") {
            Task {
              await home.saveNetwork(
                name: state.networkName,
                cidr: state.cidr,
                routerIP: state.routerIP,
                notes: state.networkNotes
              )
            }
          }
          .disabled(
            state.networkName.isEmpty || state.cidr.isEmpty
          )
        }

        Text(
          "Discovery suggestions are not trusted until you save them. TunnelDeck never changes the AX18 configuration."
        )
        .foregroundStyle(.secondary)
      }
    }
  }

  private var routerIntegration: some View {
    MetricCard(title: "Router Integration", icon: "wifi.router") {
      VStack(alignment: .leading, spacing: 10) {
        Text("TP-Link Archer AX18 · read-only client inventory")
          .font(.headline)

        TextField(
          "Router address",
          text: $state.integrationAddress
        )
        TextField(
          "Username (if firmware uses one)",
          text: $state.integrationUsername
        )
        SecureField(
          "Router password",
          text: $state.integrationPassword
        )

        HStack {
          Button("Test Connection") {
            Task {
              await home.testRouterConnection(
                address: state.integrationAddress,
                username: state.integrationUsername,
                password: state.integrationPassword
              )
            }
          }

          Button("Connect") {
            let password = state.integrationPassword
            state.integrationPassword = ""

            Task {
              await home.saveRouterIntegration(
                address: state.integrationAddress,
                username: state.integrationUsername,
                password: password
              )
            }
          }
          .buttonStyle(.borderedProminent)

          Button("Forget Credentials", role: .destructive) {
            state.integrationPassword = ""
            Task { await home.forgetRouterCredentials() }
          }

          Spacer()

          Text(home.routerState.rawValue)
            .foregroundStyle(.secondary)
        }

        if home.routerState == .authenticationRequired {
          Label(
            "Live device status from AX18 requires its administrator password. Enter it above and press Connect.",
            systemImage: "key.fill"
          )
          .font(.caption)
          .foregroundStyle(.orange)
        }

        Text(
          "Password is stored only in macOS Keychain. Router integration is inventory-only; no AX18 settings are written."
        )
        .font(.caption)
        .foregroundStyle(.secondary)
      }
    }
  }

  private var devices: some View {
    MetricCard(title: "Home Devices", icon: "desktopcomputer") {
      VStack(spacing: 10) {
        HStack {
          Picker("Filter", selection: $state.filter) {
            ForEach(HomeDeviceFilter.allCases) {
              Text($0.rawValue).tag($0)
            }
          }
          .labelsHidden()
          .frame(width: 130)

          TextField(
            "Search name, IP, MAC, hostname or vendor",
            text: $state.search
          )

          Spacer()

          Button(
            home.isProbingDevices
              ? "Probing…"
              : "Probe All"
          ) {
            Task { await home.probeAllDevices() }
          }
          .disabled(home.isProbingDevices)

          Button("Add Device Manually") {
            state.addingDevice = true
          }

          Button("Merge Selected…") {
            state.showMerge = true
          }
          .disabled(state.selection.count != 2)
        }

        if filteredDevices.isEmpty {
          ContentUnavailableView(
            "No devices discovered",
            systemImage: "network.slash",
            description: Text(
              home.diagnostics.message
                ?? "Connect the router integration or refresh while on the Home LAN."
            )
          )
        } else {
          Table(
            filteredDevices,
            selection: $state.selection
          ) {
            TableColumn("Status") { row in
              HStack {
                StatusDot(state: health(row.status))
                Text(row.status.rawValue.capitalized)
              }
            }

            TableColumn("Name", value: \.displayName)

            TableColumn("Type") {
              Text($0.customType ?? $0.type.rawValue)
            }

            TableColumn("IP") {
              Text($0.ipv4 ?? $0.ipv6 ?? "—")
                .textSelection(.enabled)
            }

            TableColumn("Internet") { device in
              Text(home.internetPolicy(for: device.id).rawValue)
            }

            TableColumn("Services") { device in
              if let probe = home.probe(for: device.id) {
                Text(probe.serviceSummary)
                  .lineLimit(1)
              } else {
                Text("Not probed")
                  .foregroundStyle(.secondary)
              }
            }

            TableColumn("Ping") { device in
              if let value = home.probe(for: device.id)?
                .latencyMilliseconds
              {
                Text(
                  String(format: "%.1f ms", value)
                )
                .monospacedDigit()
              } else {
                Text("—")
              }
            }

            TableColumn("MAC") {
              Text($0.macAddress ?? "—")
                .textSelection(.enabled)
            }

            TableColumn("Connection") {
              Text(
                $0.routerConnectionType?.rawValue ?? "—"
              )
            }

            TableColumn("Last Seen") {
              Text(HomePresence.label($0.lastSeen))
            }
          }
          .frame(minHeight: 300)

          if let device = selectedDevice {
            deviceActionPanel(device)
          }

          HStack {
            Button("Inspect / Edit") {
              state.editingDevice = selectedDevice
            }
            .disabled(state.selection.count != 1)

            Button("Delete…", role: .destructive) {
              state.pendingDeviceDelete =
                state.selection.first
              state.confirmDeviceDelete = true
            }
            .disabled(state.selection.count != 1)

            Spacer()
          }
        }
      }
      .sheet(isPresented: $state.showMerge) {
        HomeDeviceMergeSheet(
          devices: home.devices,
          selection: state.selection
        ) { source, destination in
          Task {
            await home.merge(
              source: source,
              into: destination
            )
          }
          state.showMerge = false
        }
      }
    }
  }

  @ViewBuilder
  private func deviceActionPanel(_ device: HomeDevice) -> some View {
    Divider()

    VStack(alignment: .leading, spacing: 9) {
      HStack {
        VStack(alignment: .leading, spacing: 2) {
          Text(device.displayName)
            .font(.headline)

          Text(device.ipv4 ?? device.ipv6 ?? "No IP")
            .font(.system(.caption, design: .monospaced))
            .foregroundStyle(.secondary)
        }

        Spacer()

        Picker(
          "Internet policy",
          selection: internetPolicyBinding(device.id)
        ) {
          ForEach(HomeInternetPolicy.allCases) {
            Text($0.rawValue).tag($0)
          }
        }
        .frame(width: 220)
      }

      if let probe = home.probe(for: device.id) {
        HStack(spacing: 14) {
          Label(
            probe.reachable ? "Reachable" : "No response",
            systemImage: probe.reachable
              ? "checkmark.circle.fill"
              : "xmark.circle"
          )
          .foregroundStyle(
            probe.reachable ? .green : .secondary
          )

          if let latency = probe.latencyMilliseconds {
            Text(
              String(format: "%.1f ms", latency)
            )
            .monospacedDigit()
          }

          Text(probe.serviceSummary)
            .foregroundStyle(.secondary)

          Spacer()

          Text(
            probe.checkedAt.formatted(
              date: .omitted,
              time: .standard
            )
          )
          .font(.caption)
          .foregroundStyle(.secondary)
        }
      }

      HStack {
        Button("Probe") {
          Task { await home.probeDevice(device.id) }
        }

        Button("Open Web") {
          openWeb(device)
        }
        .disabled(webURL(for: device) == nil)

        Button("SSH") {
          openSSH(device)
        }
        .disabled(!canSSH(device))

        Button("Screen Sharing") {
          openScreen(device)
        }
        .disabled(!hasPort(5900, device))

        Button("Files") {
          openFiles(device)
        }
        .disabled(!hasPort(445, device))

        Button("Copy RDP Host") {
          copyRDPHost(device)
        }
        .disabled(!hasPort(3389, device))

        Button("Wake") {
          Task { await home.wakeDevice(device.id) }
        }
        .disabled(
          device.macAddress == nil || home.gatewayKeyPath.isEmpty
        )

        Spacer()
      }

      Text(
        "Internet policy is a local TunnelDeck label. It describes how you intend AX18 to route this device; TunnelDeck does not claim to have proved that policy automatically."
      )
      .font(.caption)
      .foregroundStyle(.secondary)
    }
    .padding(10)
    .background(
      .quaternary.opacity(0.25),
      in: RoundedRectangle(cornerRadius: 10)
    )
  }

  private var profiles: some View {
    MetricCard(title: "Remote Access Profiles", icon: "lock.doc") {
      VStack(alignment: .leading, spacing: 10) {
        HStack {
          Button("Import WireGuard .conf…") {
            importProfile()
          }

          Button("Rename…") {
            state.renameProfile = selectedProfile
            state.renameValue =
              selectedProfile?
              .url
              .deletingPathExtension()
              .lastPathComponent ?? ""
            state.showRename = selectedProfile != nil
          }
          .disabled(selectedProfile == nil)

          Button("Reveal in Finder") {
            if let selectedProfile {
              ProfileStore.reveal(selectedProfile)
            }
          }
          .disabled(selectedProfile == nil)

          Button("Open with WireGuard") {
            if let selectedProfile {
              ProfileStore.open(selectedProfile)
            }
          }
          .disabled(selectedProfile == nil)

          Button("QR…") {
            if let selectedProfile {
              state.showQR(selectedProfile)
            }
          }
          .disabled(selectedProfile == nil)

          Button("Delete…", role: .destructive) {
            state.pendingProfileDelete = selectedProfile
            state.confirmProfileDelete = true
          }
          .disabled(selectedProfile == nil)
        }

        if home.profiles.isEmpty {
          Text(
            "No imported Home Access profiles. Profiles stay local with mode 0600."
          )
          .foregroundStyle(.secondary)
        } else {
          Table(
            home.profiles,
            selection: $state.profileSelection
          ) {
            TableColumn("Name", value: \.name)
            TableColumn("Type", value: \.type)
            TableColumn("Modified") {
              Text($0.modified.formatted())
            }
          }
          .frame(minHeight: 150)
        }

        Text(
          "LOCAL: Mac → Home LAN → Device\nREMOTE: Mac → WireGuard → VPS → Xiaomi/OpenWrt → Home LAN → Device\nUNKNOWN: no verified route to the configured Home LAN."
        )
        .font(.caption)
        .foregroundStyle(.secondary)
      }
    }
    .sheet(isPresented: $state.showRename) {
      VStack(spacing: 14) {
        Text("Rename Home Access Profile")
          .font(.headline)

        TextField(
          "Name",
          text: $state.renameValue
        )

        HStack {
          Button("Cancel") {
            state.showRename = false
          }

          Button("Rename") {
            if let profile = state.renameProfile {
              home.renameProfile(
                profile,
                to: state.renameValue
              )
            }
            state.showRename = false
          }
          .disabled(
            !ProfileStore.validName(state.renameValue)
          )
        }
      }
      .padding(24)
      .frame(width: 420)
    }
  }

  private var selectedDevice: HomeDevice? {
    guard state.selection.count == 1,
      let id = state.selection.first
    else { return nil }

    return home.devices.first { $0.id == id }
  }

  private var selectedProfile: LocalProfile? {
    state.profileSelection.first.flatMap { id in
      home.profiles.first { $0.id == id }
    }
  }

  private var filteredDevices: [HomeDevice] {
    home.devices.filter { device in
      let matchesFilter =
        switch state.filter {
        case .all: true
        case .online: device.status == .online
        case .offline: device.status == .offline
        case .pinned: device.isPinned
        case .unknown: device.status == .unknown
        }

      let q = state.search.lowercased()

      return matchesFilter
        && (q.isEmpty
          || [
            device.displayName,
            device.ipv4,
            device.ipv6,
            device.macAddress,
            device.hostname,
            device.vendor,
          ]
          .compactMap { $0 }
          .contains { $0.lowercased().contains(q) })
    }
  }

  private var pathText: String {
    switch home.snapshot.mode {
    case .homeLAN:
      "Mac → Home LAN → Device"
    case .remote:
      "Mac → VPS → Xiaomi/OpenWrt → Home LAN → Device"
    case .other, .unknown:
      "No verified route to Home LAN"
    }
  }

  private var gatewayHealth: HealthState {
    switch home.gatewayStatus {
    case .online: .online
    case .offline: .offline
    case .unknown: .unknown
    }
  }

  private func stateForMode(_ mode: HomeNetworkMode) -> HealthState {
    switch mode {
    case .homeLAN, .remote: .online
    case .other: .warning
    case .unknown: .unknown
    }
  }

  private func health(
    _ value: HomeDeviceReachability
  ) -> HealthState {
    switch value {
    case .online: .online
    case .offline: .offline
    case .unknown: .unknown
    }
  }

  private func metric(
    _ title: String,
    _ value: Int
  ) -> some View {
    VStack {
      Text(String(value))
        .font(.title2.bold())
      Text(title)
        .font(.caption)
        .foregroundStyle(.secondary)
    }
    .frame(maxWidth: .infinity)
  }

  private func internetPolicyBinding(
    _ id: UUID
  ) -> Binding<HomeInternetPolicy> {
    Binding(
      get: { home.internetPolicy(for: id) },
      set: { home.setInternetPolicy($0, for: id) }
    )
  }

  private func hasPort(
    _ port: Int,
    _ device: HomeDevice
  ) -> Bool {
    home.probe(for: device.id)?
      .openPorts
      .contains(port) == true
  }

  private func canSSH(_ device: HomeDevice) -> Bool {
    device.preferredSSHHost != nil || hasPort(22, device)
  }

  private func webURL(
    for device: HomeDevice
  ) -> URL? {
    if let preferred = device.preferredAccessURL,
      let url = URL(string: preferred)
    {
      return url
    }

    guard let ip = device.ipv4 ?? device.ipv6 else {
      return nil
    }

    if hasPort(8123, device) {
      return URL(string: "http://\(ip):8123")
    }

    if hasPort(443, device) {
      return URL(string: "https://\(ip)")
    }

    if hasPort(80, device) {
      return URL(string: "http://\(ip)")
    }

    return nil
  }

  private func openWeb(_ device: HomeDevice) {
    guard let url = webURL(for: device) else { return }
    NSWorkspace.shared.open(url)
  }

  private func openSSH(_ device: HomeDevice) {
    let host = device.preferredSSHHost ?? device.ipv4 ?? device.ipv6

    guard let host,
      let url = URL(string: "ssh://\(host)")
    else { return }

    NSWorkspace.shared.open(url)
  }

  private func openScreen(_ device: HomeDevice) {
    guard
      let ip = device.ipv4 ?? device.ipv6,
      let url = URL(string: "vnc://\(ip)")
    else { return }

    NSWorkspace.shared.open(url)
  }

  private func openFiles(_ device: HomeDevice) {
    guard
      let ip = device.ipv4 ?? device.ipv6,
      let url = URL(string: "smb://\(ip)")
    else { return }

    NSWorkspace.shared.open(url)
  }

  private func copyRDPHost(_ device: HomeDevice) {
    guard let ip = device.ipv4 ?? device.ipv6 else { return }

    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(
      ip,
      forType: .string
    )
  }

  private func openURL(_ value: String) {
    guard let url = URL(string: value) else { return }
    NSWorkspace.shared.open(url)
  }

  private func importProfile() {
    let panel = NSOpenPanel()
    panel.allowedContentTypes = [
      .init(filenameExtension: "conf")!
    ]
    panel.allowsMultipleSelection = false
    panel.canChooseDirectories = false

    if panel.runModal() == .OK,
      let url = panel.url
    {
      Task { await home.importProfile(from: url) }
    }
  }
}

private enum HomeDeviceFilter: String, CaseIterable, Identifiable {
  case all = "All"
  case online = "Online"
  case offline = "Offline"
  case pinned = "Pinned"
  case unknown = "Unknown"

  var id: String { rawValue }
}

@MainActor
private final class HomeAccessScreenState: ObservableObject {
  @Published var filter: HomeDeviceFilter = .all
  @Published var search = ""
  @Published var selection = Set<UUID>()
  @Published var profileSelection = Set<String>()

  @Published var networkName = "Home"
  @Published var cidr = ""
  @Published var routerIP = ""
  @Published var networkNotes = ""

  @Published var integrationAddress = ""
  @Published var integrationUsername = ""
  @Published var integrationPassword = ""

  @Published var gatewayAddress = "192.168.0.2"
  @Published var gatewayVPNAddress = "10.66.66.6"
  @Published var gatewayUsername = "root"
  @Published var gatewayKeyPath = ""

  @Published var addingDevice = false
  @Published var editingDevice: HomeDevice?
  @Published var pendingDeviceDelete: UUID?
  @Published var confirmDeviceDelete = false
  @Published var showMerge = false

  @Published var pendingProfileDelete: LocalProfile?
  @Published var confirmProfileDelete = false
  @Published var showRename = false
  @Published var renameProfile: LocalProfile?
  @Published var renameValue = ""

  @Published var qrVisible = false
  @Published var qrImage: NSImage?
  @Published var qrName = ""

  func reflect(_ network: HomeNetwork?) {
    guard let network else { return }

    networkName = network.name
    cidr = network.cidr
    routerIP = network.routerIP
    networkNotes = network.notes
  }

  func reflectRouter(_ home: HomeAccessController) {
    integrationAddress =
      home.routerAddress.isEmpty
      ? home.snapshot.defaultGateway ?? ""
      : home.routerAddress
    integrationUsername = home.routerUsername
  }

  func reflectGateway(
    _ home: HomeAccessController,
    fallbackKeyPath: String
  ) {
    gatewayAddress = home.gatewayAddress
    gatewayVPNAddress = home.gatewayVPNAddress
    gatewayUsername = home.gatewayUsername
    gatewayKeyPath =
      home.gatewayKeyPath.isEmpty
      ? fallbackKeyPath
      : home.gatewayKeyPath
  }

  func showQR(_ profile: LocalProfile) {
    guard let content = try? ProfileStore.content(profile) else { return }

    qrName = profile.name
    qrImage = ProfileStore.qrImage(for: content)
    qrVisible = qrImage != nil
  }
}

private struct ManualHomeDeviceValue {
  var name = ""
  var type: HomeDeviceType = .unknown
  var ip = ""
  var mac = ""
  var hostname = ""
  var notes = ""
}

private struct ManualHomeDeviceSheet: View {
  @Environment(\.dismiss) var dismiss
  @State private var value = ManualHomeDeviceValue()

  let save: (ManualHomeDeviceValue) -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      Text("Add Home Device")
        .font(.title2.bold())

      Form {
        TextField("Name", text: $value.name)

        Picker("Type", selection: $value.type) {
          ForEach(HomeDeviceType.allCases) {
            Text($0.rawValue).tag($0)
          }
        }

        TextField("IP (optional)", text: $value.ip)
        TextField("MAC (optional)", text: $value.mac)
        TextField("Hostname (optional)", text: $value.hostname)
        TextField("Notes", text: $value.notes)
      }

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button("Add") {
          save(value)
          dismiss()
        }
        .buttonStyle(.borderedProminent)
        .disabled(
          value.name
            .trimmingCharacters(in: .whitespaces)
            .isEmpty
        )
      }
    }
    .padding(24)
    .frame(width: 500)
  }
}

private struct HomeDeviceEditor: View {
  @Environment(\.dismiss) var dismiss

  @State var device: HomeDevice
  @State private var history: [HomeDeviceObservation] = []

  let loadHistory: () async -> [HomeDeviceObservation]
  let refresh: () async -> Void
  let save: (HomeDevice) -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      Text("Home Device")
        .font(.title2.bold())

      Form {
        TextField(
          "Name",
          text: $device.displayName
        )

        Picker("Type", selection: $device.type) {
          ForEach(HomeDeviceType.allCases) {
            Text($0.rawValue).tag($0)
          }
        }

        if device.type == .custom {
          TextField(
            "Custom type",
            text: optionalBinding(\.customType)
          )
        }

        Toggle(
          "Pinned",
          isOn: $device.isPinned
        )

        TextField(
          "Notes",
          text: optionalBinding(\.notes)
        )

        TextField(
          "Preferred URL",
          text: optionalBinding(\.preferredAccessURL)
        )

        TextField(
          "Preferred SSH host",
          text: optionalBinding(\.preferredSSHHost)
        )

        LabeledContent("IPv4", value: device.ipv4 ?? "—")
        LabeledContent("IPv6", value: device.ipv6 ?? "—")
        LabeledContent("MAC", value: device.macAddress ?? "—")
        LabeledContent("Hostname", value: device.hostname ?? "—")
        LabeledContent(
          "Router name",
          value: device.routerDisplayName ?? "—"
        )
        LabeledContent(
          "Connection",
          value: device.routerConnectionType?.rawValue ?? "Unknown"
        )
        LabeledContent(
          "Vendor",
          value: device.vendor ?? "Unknown"
        )
        LabeledContent(
          "Sources",
          value: device.discoverySources
            .map(\.rawValue)
            .sorted()
            .joined(separator: ", ")
        )
        LabeledContent(
          "First seen",
          value: device.firstSeen.formatted()
        )
        LabeledContent(
          "Last seen",
          value: HomePresence.label(device.lastSeen)
        )
        LabeledContent(
          "Evidence",
          value: device.reachabilityEvidence ?? "Insufficient evidence"
        )
      }

      GroupBox("Presence · last 30 days") {
        if history.isEmpty {
          Text("No confirmed observations")
            .foregroundStyle(.secondary)
            .frame(
              maxWidth: .infinity,
              alignment: .leading
            )
        } else {
          VStack(alignment: .leading) {
            ForEach(history.suffix(8).reversed()) { value in
              Text(
                "\(HomePresence.label(value.timestamp)) · \(value.source.rawValue.uppercased()) · \(value.ip ?? "address unavailable")"
              )
              .font(.caption)
            }
          }
          .frame(
            maxWidth: .infinity,
            alignment: .leading
          )
        }
      }

      HStack {
        Button("Refresh Device") {
          Task {
            await refresh()
            history = await loadHistory()
          }
        }

        if let ip = device.ipv4 ?? device.ipv6 {
          Button("Copy IP") {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(
              ip,
              forType: .string
            )
          }
        }

        if let value = device.preferredAccessURL,
          let url = URL(string: value)
        {
          Button("Open Preferred URL") {
            NSWorkspace.shared.open(url)
          }
        }

        if let host = device.preferredSSHHost,
          let url = URL(string: "ssh://\(host)")
        {
          Button("SSH") {
            NSWorkspace.shared.open(url)
          }
        }

        Spacer()

        Button("Cancel") {
          dismiss()
        }

        Button("Save") {
          save(device)
          dismiss()
        }
        .buttonStyle(.borderedProminent)
      }
    }
    .padding(24)
    .frame(width: 600)
    .task {
      history = await loadHistory()
    }
  }

  private func optionalBinding(
    _ keyPath: WritableKeyPath<HomeDevice, String?>
  ) -> Binding<String> {
    Binding(
      get: { device[keyPath: keyPath] ?? "" },
      set: {
        device[keyPath: keyPath] =
          $0.isEmpty ? nil : $0
      }
    )
  }
}

private struct HomeDeviceMergeSheet: View {
  @Environment(\.dismiss) var dismiss

  let devices: [HomeDevice]
  let selection: Set<UUID>
  let merge: (UUID, UUID) -> Void

  @State private var destination: UUID?

  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      Text("Merge Duplicate Devices")
        .font(.title2.bold())

      Text(
        "Choose the identity to keep. Addresses and observation history from the other identity will be retained."
      )
      .foregroundStyle(.secondary)

      Picker("Keep", selection: $destination) {
        Text("Choose…").tag(UUID?.none)

        ForEach(
          devices.filter { selection.contains($0.id) }
        ) {
          Text($0.displayName)
            .tag(Optional($0.id))
        }
      }

      HStack {
        Spacer()

        Button("Cancel") {
          dismiss()
        }

        Button("Merge") {
          if let destination,
            let source = selection.first(
              where: { $0 != destination }
            )
          {
            merge(source, destination)
          }
          dismiss()
        }
        .buttonStyle(.borderedProminent)
        .disabled(destination == nil)
      }
    }
    .padding(24)
    .frame(width: 480)
  }
}
