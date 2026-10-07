import Foundation

enum InfrastructureFlowKind:String,Sendable,CaseIterable{
    case direct="DIRECT",foreign="FOREIGN",service="SERVICE WG",dns="DNS",local="LAN"
}

struct InfrastructureTunnelSnapshot:Identifiable,Sendable,Equatable{
    var id:String{name}
    var name:String
    var role:String
    var transport:String
    var localAddress:String?
    var peerAddress:String?
    var endpoint:String?
    var listenPort:Int?
    var mtu:Int?
    var latestHandshake:Date?
    var receivedBytes:UInt64=0
    var sentBytes:UInt64=0
    var state:HealthState = .unknown
    var observedOn:[String]=[]
    var evidence:String?
}

struct OpenWrtGatewaySnapshot:Sendable,Equatable{
    var state:HealthState = .unknown
    var host:String?
    var hostname:String?
    var model:String?
    var version:String?
    var uptime:String?
    var lanIPv4:String?
    var defaultGateway:String?
    var defaultInterface:String?
    var dhcpServer:Bool?
    var dnsServer:Bool?
    var upstreamDNS:[String]=[]
    var filterAAAA:Bool?
    var ipv4Forwarding:Bool?
    var ruPrefixCount:Int?
    var foreignMark:String?
    var foreignPriority:Int?
    var foreignTable:String?
    var foreignInterface:String?
    var nftEvidence:[String]=[]
    var directExceptions:[String]=[]
    var scripts:[String]=[]
    var managementInterface:String?
    var observedAt:Date?
    var evidence:String?
}

struct VPSPolicySnapshot:Sendable,Equatable{
    var state:HealthState = .unknown
    var publicInterface:String?
    var ruPrefixCount:Int?
    var ruMark:String?
    var ruPriority:Int?
    var ruTable:String?
    var homeExitInterface:String?
    var observedAt:Date?
    var evidence:String?
}

struct HomeInfrastructureSnapshot:Sendable,Equatable{
    var gateway=OpenWrtGatewaySnapshot()
    var vpsPolicy=VPSPolicySnapshot()
    var gatewayTunnels:[InfrastructureTunnelSnapshot]=[]
    var vpsTunnels:[InfrastructureTunnelSnapshot]=[]
    var homeCIDR:String?
    var homeDeviceCount=0
    var observedAt:Date?
    var lastAttemptAt:Date?
    var sourceSummary="Not discovered"

    func tunnel(named name:String?)->InfrastructureTunnelSnapshot?{
        guard let name else{return nil}
        return gatewayTunnels.first{$0.name==name} ?? vpsTunnels.first{$0.name==name}
    }

    var foreignTunnel:InfrastructureTunnelSnapshot?{tunnel(named:gateway.foreignInterface)}
    var homeExitTunnel:InfrastructureTunnelSnapshot?{tunnel(named:vpsPolicy.homeExitInterface)}
    var managementTunnel:InfrastructureTunnelSnapshot?{tunnel(named:gateway.managementInterface)}

    var directPathConfirmed:Bool{gateway.state == .online && gateway.defaultGateway != nil}
    var foreignPathConfirmed:Bool{gateway.state == .online && gateway.foreignMark != nil && gateway.foreignTable != nil && gateway.foreignInterface != nil}
    var remoteRUPathConfirmed:Bool{vpsPolicy.state == .online && vpsPolicy.ruMark != nil && vpsPolicy.ruTable != nil && vpsPolicy.homeExitInterface != nil}
    var managementPathConfirmed:Bool{gateway.state == .online && gateway.managementInterface != nil}
    var dnsForeignConfirmed:Bool{
        guard let mark=gateway.foreignMark else{return false}
        return gateway.nftEvidence.contains{line in line.contains(mark) && (line.contains(" dport 53") || line.contains("sport 53") || line.contains(" udp ") || line.contains(" tcp "))}
    }
}
