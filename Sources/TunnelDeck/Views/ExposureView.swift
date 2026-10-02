import SwiftUI

struct ExposureView: View {
    @EnvironmentObject var model: AppViewModel
    var body: some View { VStack(spacing: 0) { HStack { Text("Reachability is evidence-based. Wildcard binds without firewall proof remain Unknown.").foregroundStyle(.secondary); Spacer(); Button("Refresh Exposure") { Task { await model.refreshSecurityAudit() } }.disabled(model.isRefreshingSecurity) }.padding(); Table(model.exposureEndpoints) { TableColumn("Service") { endpoint in Text(model.exposureName(endpoint)) }; TableColumn("Protocol") { Text($0.protocolName.rawValue.uppercased()) }; TableColumn("Port") { Text(String($0.port)) }; TableColumn("Bind addresses") { Text($0.bindAddresses.joined(separator: ", ")) }; TableColumn("IP") { Text($0.addressFamily.rawValue) }; TableColumn("Firewall evidence") { Text($0.firewallEvidence.isEmpty ? "None" : $0.firewallEvidence.joined(separator: "; ")).lineLimit(2) }; TableColumn("Classification") { endpoint in Text(label(endpoint.classification)).fontWeight(.semibold) }; TableColumn("Explanation", value: \.explanation) } } }
    private func label(_ value: ExposureClassification) -> String { switch value { case .publicInternet: "Public"; case .vpnOnly: "VPN only"; case .privateLAN: "Private LAN"; case .loopback: "Loopback"; case .firewallBlocked: "Firewall blocked"; case .unknown: "Unknown" } }
}
