import SwiftUI

struct FleetOverviewView: View {
    @EnvironmentObject var model: AppViewModel
    private let columns = [GridItem(.adaptive(minimum: 330), spacing: 16)]
    var body: some View { ScrollView { if model.fleetSummaries.isEmpty { ContentUnavailableView("No infrastructure nodes", systemImage: "server.rack", description: Text("Save the current VPS in Settings to add the first node.")).padding(40) } else { LazyVGrid(columns: columns, alignment: .leading, spacing: 16) { ForEach(model.fleetSummaries) { node in Button { model.selectServer(node.id); model.selectedSection = .dashboard } label: { MetricCard(title: node.name, icon: "server.rack") { VStack(spacing: 8) { HStack { StatusDot(state: node.overall); Text(node.role).foregroundStyle(.secondary); Spacer(); Text(observationLabel(node)).fontWeight(.semibold) }; HStack { state("SSH", node.ssh); state("wg0", node.wireGuard); state("AdGuard", node.adGuard); state("AntiZapret", node.antiZapret) }; Divider(); HStack { metric("CPU", node.cpu); metric("RAM", node.memory); metric("Disk", node.disk); metric("Ping", node.ping, "ms") }; KeyValueRow(key: "Peers", value: node.peersOnline.map { "\($0)/\(node.peersTotal ?? 0)" } ?? "Unknown"); KeyValueRow(key: "Exposure warnings", value: String(node.exposureWarnings)); KeyValueRow(key: "Active incidents", value: String(node.activeIncidents)) } } }.buttonStyle(.plain) } }.padding(20) } } }
    private func state(_ name: String, _ value: HealthState) -> some View { VStack { StatusDot(state: value); Text(name).font(.caption2) }.frame(maxWidth: .infinity) }
    private func metric(_ name: String, _ value: Double?, _ suffix: String = "%") -> some View { VStack { Text(name).font(.caption2).foregroundStyle(.secondary); Text(value.map { String(format: "%.0f%@", $0, suffix) } ?? "—").monospacedDigit() }.frame(maxWidth: .infinity) }
    private func observationLabel(_ node: FleetNodeSummary) -> String { let freshness=ObservationFreshness(lastObservedAt:node.lastObservedAt,now:Date(),staleAfter:max(model.settings.pollingInterval*3,120));switch freshness.state{case .unknown:return "Unknown · never checked";case .stale:return "Stale · checked \(node.lastObservedAt!.formatted(.relative(presentation:.numeric)))";case .live:return "\(node.overall.rawValue.capitalized) · checked \(node.lastObservedAt!.formatted(.relative(presentation:.numeric)))"} }
}

struct TopologyView: View {
    @EnvironmentObject var model: AppViewModel

    private struct Node:Identifiable{
        let id:String
        let title:String
        let detail:String?
        let state:HealthState
        init(_ title:String,_ state:HealthState,_ detail:String?=nil){self.id="\(title)|\(detail ?? "")";self.title=title;self.detail=detail;self.state=state}
    }

    var body: some View {
        ScrollView {
            VStack(alignment:.leading,spacing:20) {
                HStack(alignment:.firstTextBaseline) {
                    VStack(alignment:.leading,spacing:4) {
                        Text("Live architecture").font(.title2.bold())
                        Text("Nodes and routes come from the latest read-only VPS, OpenWrt and Home LAN discovery. Missing evidence stays Unknown.")
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if let date=model.homeInfrastructure.observedAt {
                        Text("Last discovery \(date.formatted(.relative(presentation:.numeric)))").font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text("Never discovered").font(.caption).foregroundStyle(.secondary)
                    }
                }

                topologySection("Home split routing","Home clients use the OpenWrt policy gateway. DIRECT and foreign paths are shown independently.") {
                    flowLine(.local,label:"LAN",nodes:[
                        Node("Home Devices",homeLANState,"\(model.homeInfrastructure.homeDeviceCount) known"),
                        gatewayNode
                    ])
                    flowLine(.direct,label:directLabel,nodes:[
                        gatewayNode,
                        uplinkNode,
                        Node("RU Internet",model.homeInfrastructure.directPathConfirmed && uplinkState == .online ? .unknown:.unknown,"Route evidence only")
                    ])
                    flowLine(.foreign,label:foreignLabel,nodes:[
                        gatewayNode,
                        tunnelNode(model.homeInfrastructure.foreignTunnel,fallback:"Foreign Tunnel"),
                        Node(model.activeNodeName,model.system.health,model.system.publicIPv4),
                        Node("Foreign Internet",model.system.publicIPv4 == "—" ? .unknown:.online,"VPS egress")
                    ])
                }

                topologySection("Remote WireGuard","Remote clients enter through VPS wg0. Foreign traffic exits at the VPS; RU traffic may return home through the discovered home-exit policy.") {
                    flowLine(.service,label:"Remote access",nodes:[
                        Node("Remote WG Client",remoteClientState,remoteClientDetail),
                        Node("VPS wg0",model.wireGuard.state,model.wireGuard.address),
                        Node("Foreign Internet",model.system.publicIPv4 == "—" ? .unknown:.online,model.system.publicIPv4)
                    ])
                    flowLine(.direct,label:remoteRULabel,nodes:[
                        Node("VPS wg0",model.wireGuard.state,model.wireGuard.address),
                        tunnelNode(model.homeInfrastructure.homeExitTunnel,fallback:"RU Home Exit"),
                        gatewayNode,
                        uplinkNode,
                        Node("Russian Internet",.unknown,"Path observed; external reachability not assumed")
                    ])
                }

                topologySection("Remote Home LAN management","The management path is discovered from the route between the VPS WireGuard subnet and the Home LAN gateway.") {
                    flowLine(.service,label:managementLabel,nodes:[
                        Node("Remote WG Client",remoteClientState,remoteClientDetail),
                        Node("VPS wg0",model.wireGuard.state,model.wireGuard.address),
                        tunnelNode(model.homeInfrastructure.managementTunnel,fallback:"Management Tunnel"),
                        gatewayNode,
                        Node("Home LAN \(model.homeInfrastructure.homeCIDR ?? "Unknown")",homeLANState,"\(model.homeInfrastructure.homeDeviceCount) known devices")
                    ])
                }

                topologySection("DNS","Home DNS is served by the OpenWrt gateway. The upstream foreign path is only marked confirmed when nftables evidence ties DNS traffic to the discovered foreign mark.") {
                    flowLine(.dns,label:dnsLabel,nodes:[
                        Node("Home Client",homeLANState,nil),
                        Node("Xiaomi DNS",model.homeInfrastructure.gateway.dnsServer == true ? model.homeInfrastructure.gateway.state:.unknown,model.homeInfrastructure.gateway.host),
                        tunnelNode(model.homeInfrastructure.foreignTunnel,fallback:"Foreign Tunnel"),
                        Node(model.activeNodeName,model.system.health,"Foreign exit"),
                        Node("Cloudflare DNS",.unknown,model.homeInfrastructure.gateway.upstreamDNS.isEmpty ? "Upstream not observed":model.homeInfrastructure.gateway.upstreamDNS.joined(separator:", "))
                    ])
                }

                GroupBox("Discovery evidence") {
                    Grid(alignment:.leading,horizontalSpacing:16,verticalSpacing:8) {
                        GridRow { Text("OpenWrt").foregroundStyle(.secondary); Text(model.homeInfrastructure.gateway.evidence ?? "Unknown") }
                        GridRow { Text("VPS policy").foregroundStyle(.secondary); Text(model.homeInfrastructure.vpsPolicy.evidence ?? "Unknown") }
                        GridRow { Text("Foreign policy").foregroundStyle(.secondary); Text(foreignLabel) }
                        GridRow { Text("Remote RU policy").foregroundStyle(.secondary); Text(remoteRULabel) }
                        GridRow { Text("Management").foregroundStyle(.secondary); Text(managementLabel) }
                    }.padding(8)
                }
            }
            .padding(24)
            .frame(maxWidth:1200,alignment:.leading)
        }
    }

    @ViewBuilder
    private func topologySection<Content:View>(_ title:String,_ subtitle:String,@ViewBuilder content:()->Content)->some View{
        GroupBox {
            VStack(alignment:.leading,spacing:12) {
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
                content()
            }.padding(8)
        } label: {
            Text(title).font(.headline)
        }
    }

    private func flowLine(_ kind:InfrastructureFlowKind,label:String,nodes:[Node])->some View{
        ScrollView(.horizontal,showsIndicators:false) {
            HStack(spacing:10) {
                badge(kind,label:label)
                ForEach(Array(nodes.enumerated()),id:\.offset){index,node in
                    if index>0 {
                        Image(systemName:"arrow.right")
                            .font(.headline)
                            .foregroundStyle(flowColor(kind))
                    }
                    nodeView(node)
                }
            }
            .padding(.vertical,4)
        }
    }

    private func nodeView(_ node:Node)->some View{
        HStack(spacing:8) {
            StatusDot(state:node.state)
            VStack(alignment:.leading,spacing:2) {
                Text(node.title).fontWeight(.semibold).lineLimit(1)
                if let detail=node.detail,!detail.isEmpty{Text(detail).font(.caption2).foregroundStyle(.secondary).lineLimit(2)}
            }
        }
        .padding(.horizontal,12).padding(.vertical,9)
        .frame(minWidth:150,alignment:.leading)
        .background(.quaternary.opacity(0.35),in:RoundedRectangle(cornerRadius:10))
    }

    private func badge(_ kind:InfrastructureFlowKind,label:String)->some View{
        Text(label)
            .font(.caption2.bold())
            .padding(.horizontal,8).padding(.vertical,5)
            .foregroundStyle(flowColor(kind))
            .background(flowColor(kind).opacity(0.12),in:Capsule())
    }

    private func flowColor(_ kind:InfrastructureFlowKind)->Color{
        switch kind{
        case .direct:return .green
        case .foreign:return .blue
        case .service:return .orange
        case .dns:return .purple
        case .local:return .gray
        }
    }

    private var gatewayNode:Node{
        let gateway=model.homeInfrastructure.gateway
        return Node("Xiaomi OpenWrt",gateway.state,gateway.lanIPv4 ?? gateway.host)
    }

    private var uplinkNode:Node{
        Node("AX18 · Home Uplink",uplinkState,model.home.network?.routerIP)
    }

    private func tunnelNode(_ tunnel:InfrastructureTunnelSnapshot?,fallback:String)->Node{
        Node(tunnel?.name ?? fallback,tunnel?.state ?? .unknown,tunnel.map{"\($0.role) · \($0.localAddress ?? "address unknown")"} ?? "Not discovered")
    }

    private var homeLANState:HealthState{
        switch model.home.snapshot.mode{case .homeLAN,.remote:return .online;case .other,.unknown:return .unknown}
    }

    private var uplinkState:HealthState{
        if model.home.routerState == .connected{return .online}
        guard let ip=model.home.network?.routerIP,let device=model.home.devices.first(where:{$0.ipv4==ip}) else{return .unknown}
        switch device.status{case .online:return .online;case .offline:return .offline;case .unknown:return .unknown}
    }

    private var remoteClientState:HealthState{
        if model.wireGuard.peers.contains(where:{$0.status == .online}){return .online}
        return model.wireGuard.peers.isEmpty ? .unknown:.offline
    }

    private var remoteClientDetail:String{"\(model.wireGuard.peers.filter{$0.status == .online}.count)/\(model.wireGuard.peers.count) peers online"}

    private var directLabel:String{
        guard model.homeInfrastructure.directPathConfirmed else{return "DIRECT · Unknown"}
        return "DIRECT · via \(model.homeInfrastructure.gateway.defaultGateway ?? "?")"
    }

    private var foreignLabel:String{
        let g=model.homeInfrastructure.gateway
        guard model.homeInfrastructure.foreignPathConfirmed else{return "FOREIGN · Unknown"}
        return "FOREIGN · \(g.foreignMark ?? "?") → table \(g.foreignTable ?? "?") → \(g.foreignInterface ?? "?")"
    }

    private var remoteRULabel:String{
        let v=model.homeInfrastructure.vpsPolicy
        guard model.homeInfrastructure.remoteRUPathConfirmed else{return "RU RETURN · Unknown"}
        return "RU RETURN · \(v.ruMark ?? "?") → table \(v.ruTable ?? "?") → \(v.homeExitInterface ?? "?")"
    }

    private var managementLabel:String{
        model.homeInfrastructure.managementPathConfirmed ? "MANAGEMENT · \(model.homeInfrastructure.gateway.managementInterface ?? "?")":"MANAGEMENT · Unknown"
    }

    private var dnsLabel:String{
        model.homeInfrastructure.dnsForeignConfirmed ? "DNS · foreign policy confirmed":"DNS · upstream policy Unknown"
    }
}
