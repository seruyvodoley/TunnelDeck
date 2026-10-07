import Foundation
import Testing
@testable import TunnelDeck

@Test func taggedDiscoveryOutputSplitsSections(){
    let text="""
    __TD_ONE__
    alpha
    beta
    __TD_TWO__
    gamma
    """
    let sections=TaggedDiscoveryOutput.sections(text)
    #expect(sections["ONE"]=="alpha\nbeta")
    #expect(sections["TWO"]=="gamma")
}

@Test func liveInfrastructureParserDiscoversDynamicHomePoliciesAndTunnels(){
    let now=Date()
    let vpsText="""
    __TD_RULES__
    0: from all lookup local
    1067: from all fwmark 0x67 lookup 167
    32766: from all lookup main
    __TD_ROUTES__
    default via 91.196.32.1 dev ens3
    default dev homeexit table 167
    10.67.0.0/30 dev homeexit scope link src 10.67.0.1
    __TD_INTERFACES__
    ens3             UP             91.196.32.58/24
    wg0              UNKNOWN        10.66.66.1/24
    homeexit         UNKNOWN        10.67.0.1/30
    __TD_LINKS__
    7: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 state UNKNOWN
    8: homeexit: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1280 state UNKNOWN
    __TD_WG__
    interface: wg0
      listening port: 51820
    peer: abcdefghijklmnopqrstuvwxyz0123456789ABCDE=
      allowed ips: 10.66.66.2/32
      latest handshake: 12 seconds ago
      transfer: 1.00 MiB received, 2.00 MiB sent
    interface: homeexit
      listening port: 51821
    peer: bcdefghijklmnopqrstuvwxyz0123456789ABCDEF=
      endpoint: 192.0.2.20:51821
      allowed ips: 10.67.0.2/32
      latest handshake: 20 seconds ago
      transfer: 3.00 MiB received, 4.00 MiB sent
    __TD_AWG__

    __TD_RU_COUNT__
    11460
    __TD_NFT_HINTS__
    meta mark set 0x67
    """
    let vps=HomeInfrastructureParser.vps(vpsText,commandSucceeded:true,now:now,handshakeTimeout:180)
    #expect(vps.policy.publicInterface=="ens3")
    #expect(vps.policy.ruPrefixCount==11460)
    #expect(vps.policy.ruMark=="0x67")
    #expect(vps.policy.ruPriority==1067)
    #expect(vps.policy.ruTable=="167")
    #expect(vps.policy.homeExitInterface=="homeexit")
    #expect(vps.tunnels.first(where:{$0.name=="homeexit"})?.role=="Remote RU Home Exit")
    #expect(vps.tunnels.first(where:{$0.name=="wg0"})?.role=="Remote Access VPN")

    let openWrtText="""
    __TD_BOARD__
    {"hostname":"TunnelDeck-Gateway","model":"Xiaomi Mi Router 4C","release":{"description":"OpenWrt 25.12.5"}}
    __TD_UPTIME__
    04:00:00 up 1 day
    __TD_INTERFACES__
    br-lan           UP             192.168.0.2/24
    warp0            UNKNOWN        10.68.0.2/30
    homeexit         UNKNOWN        10.67.0.2/30
    tdhome           UNKNOWN        10.66.66.6/32
    __TD_LINKS__
    4: br-lan: <BROADCAST,MULTICAST,UP> mtu 1500 state UP
    11: warp0: <POINTOPOINT,NOARP,UP> mtu 1280 state UNKNOWN
    12: homeexit: <POINTOPOINT,NOARP,UP> mtu 1280 state UNKNOWN
    13: tdhome: <POINTOPOINT,NOARP,UP> mtu 1420 state UNKNOWN
    __TD_ROUTES__
    default via 192.168.0.1 dev br-lan
    default dev warp0 table 168
    10.66.66.0/24 dev tdhome scope link
    10.67.0.0/30 dev homeexit scope link src 10.67.0.2
    __TD_RULES__
    0: from all lookup local
    1168: from all fwmark 0x68 lookup 168
    32766: from all lookup main
    __TD_FORWARD__
    1
    __TD_DHCP__
    ignore=
    filter_aaaa=1
    servers=1.1.1.1 1.0.0.1
    dnsmasq=active
    __TD_WG__
    interface: homeexit
    peer: bcdefghijklmnopqrstuvwxyz0123456789ABCDEF=
      endpoint: 91.196.32.58:51821
      allowed ips: 10.67.0.1/32
      latest handshake: 15 seconds ago
      transfer: 5.00 MiB received, 6.00 MiB sent
    interface: tdhome
    peer: cdefghijklmnopqrstuvwxyz0123456789ABCDEFG=
      endpoint: 91.196.32.58:51820
      allowed ips: 10.66.66.1/32
      latest handshake: 10 seconds ago
      transfer: 7.00 MiB received, 8.00 MiB sent
    __TD_AWG__
    interface: warp0
    peer: defghijklmnopqrstuvwxyz0123456789ABCDEFGH=
      endpoint: 91.196.32.58:51831
      allowed ips: 0.0.0.0/0
      latest handshake: 5 seconds ago
      transfer: 9.00 MiB received, 10.00 MiB sent
    __TD_RU4__
    table inet tunneldeck {
      set ru4 {
        type ipv4_addr
        flags interval
        elements = { 5.8.0.0/13, 31.13.16.0/20, 37.9.64.0/18 }
      }
    }
    __TD_NFT_HINTS__
    udp dport 53 meta mark set 0x68
    meta mark 0x68 masquerade
    __TD_DIRECT__
    ip saddr 192.168.0.245 return
    ip saddr 192.168.0.110 return
    __TD_SCRIPTS__
    /usr/local/sbin/tunneldeck-home-split:present
    /etc/init.d/tunneldeck-homeexit:present
    /etc/init.d/tunneldeck-tdhome:present
    """
    let open=HomeInfrastructureParser.openWrt(openWrtText,host:"192.168.0.2",commandSucceeded:true,now:now,handshakeTimeout:180,vpsTunnels:vps.tunnels)
    #expect(open.gateway.state == .online)
    #expect(open.gateway.hostname=="TunnelDeck-Gateway")
    #expect(open.gateway.model=="Xiaomi Mi Router 4C")
    #expect(open.gateway.version=="OpenWrt 25.12.5")
    #expect(open.gateway.lanIPv4=="192.168.0.2/24")
    #expect(open.gateway.defaultGateway=="192.168.0.1")
    #expect(open.gateway.defaultInterface=="br-lan")
    #expect(open.gateway.dhcpServer==true)
    #expect(open.gateway.dnsServer==true)
    #expect(open.gateway.filterAAAA==true)
    #expect(open.gateway.ipv4Forwarding==true)
    #expect(open.gateway.ruPrefixCount==3)
    #expect(open.gateway.foreignMark=="0x68")
    #expect(open.gateway.foreignPriority==1168)
    #expect(open.gateway.foreignTable=="168")
    #expect(open.gateway.foreignInterface=="warp0")
    #expect(open.gateway.managementInterface=="tdhome")
    #expect(open.gateway.upstreamDNS==["1.1.1.1","1.0.0.1"])
    #expect(open.gateway.directExceptions.contains("192.168.0.245"))
    #expect(open.gateway.directExceptions.contains("192.168.0.110"))

    let foreign=open.tunnels.first(where:{$0.name=="warp0"})
    #expect(foreign?.transport=="AmneziaWG")
    #expect(foreign?.role=="Foreign Exit")
    #expect(foreign?.localAddress=="10.68.0.2/30")
    #expect(foreign?.peerAddress=="10.68.0.1/30")
    #expect(foreign?.endpoint=="91.196.32.58:51831")
    #expect(foreign?.mtu==1280)
    #expect(open.tunnels.first(where:{$0.name=="homeexit"})?.role=="Remote RU Home Exit")
    #expect(open.tunnels.first(where:{$0.name=="tdhome"})?.role=="Remote Home LAN Management")

    let snapshot=HomeInfrastructureSnapshot(gateway:open.gateway,vpsPolicy:vps.policy,gatewayTunnels:open.tunnels,vpsTunnels:vps.tunnels,homeCIDR:"192.168.0.0/24",homeDeviceCount:15,observedAt:now,lastAttemptAt:now,sourceSummary:"fixture")
    #expect(snapshot.directPathConfirmed)
    #expect(snapshot.foreignPathConfirmed)
    #expect(snapshot.remoteRUPathConfirmed)
    #expect(snapshot.managementPathConfirmed)
    #expect(snapshot.dnsForeignConfirmed)
}

@Test func missingTopologyEvidenceStaysUnknown(){
    let open=HomeInfrastructureParser.openWrt("",host:"192.168.0.2",commandSucceeded:false,now:Date(),handshakeTimeout:180,vpsTunnels:[])
    let vps=HomeInfrastructureParser.vps("",commandSucceeded:false,now:Date(),handshakeTimeout:180)
    #expect(open.gateway.state == .unknown)
    #expect(vps.policy.state == .unknown)
    #expect(open.tunnels.isEmpty)
    #expect(vps.tunnels.isEmpty)
}
