import Foundation
import Testing
@testable import TunnelDeck

@Test func networkRadarSocketParsing() {
    let input = """
    tcp ESTAB 0 0 10.66.66.1:22 10.66.66.2:51234 users:((\"sshd\",pid=100,fd=4))
    tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))
    udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*
    """

    let rows = NetworkRadarParser.sockets(input)

    #expect(rows.count == 1)
    #expect(rows[0].remoteHost == "10.66.66.2")
    #expect(rows[0].remotePort == "51234")
    #expect(rows[0].remoteScope == "VPN")
    #expect(rows[0].process.contains("sshd"))
}

@Test func networkRadarConntrackParsing() {
    let input = """
    __TD_CONNTRACK__
    tcp 6 431999 ESTABLISHED src=10.66.66.2 dst=104.18.33.45 sport=50123 dport=443 src=104.18.33.45 dst=91.196.32.58 sport=443 dport=50123 [ASSURED] mark=0 use=1
    udp 17 25 src=10.66.66.3 dst=1.1.1.1 sport=53000 dport=53 src=1.1.1.1 dst=91.196.32.58 sport=53 dport=53000 [ASSURED] mark=0 use=1
    """

    #expect(NetworkRadarParser.conntrackAvailable(input))

    let rows = NetworkRadarParser.conntrack(input)

    #expect(rows.count == 2)
    #expect(rows[0].sourceScope == "VPN")
    #expect(rows.contains { $0.destinationHost == "104.18.33.45" && $0.destinationPort == "443" })
    #expect(rows.contains { $0.destinationHost == "1.1.1.1" && $0.destinationPort == "53" })
}

@Test func networkRadarBlockedProbeAggregation() {
    let input = """
    Oct 07 kernel: TUNNELDECK_DROP IN=ens3 SRC=203.0.113.10 DST=91.196.32.58 PROTO=TCP SPT=50000 DPT=22
    Oct 07 kernel: TUNNELDECK_DROP IN=ens3 SRC=203.0.113.10 DST=91.196.32.58 PROTO=TCP SPT=50001 DPT=22
    Oct 07 kernel: UFW BLOCK IN=ens3 SRC=198.51.100.9 DST=91.196.32.58 PROTO=UDP SPT=41000 DPT=51820
    """

    let rows = NetworkRadarParser.blocked(input)

    #expect(rows.count == 2)
    #expect(rows.first { $0.remoteIP == "203.0.113.10" }?.count == 2)
    #expect(rows.first { $0.remoteIP == "203.0.113.10" }?.destinationPort == "22")
}

@Test func networkRadarScopeClassification() {
    #expect(NetworkRadarParser.scope("10.66.66.2") == "VPN")
    #expect(NetworkRadarParser.scope("192.168.0.20") == "Private")
    #expect(NetworkRadarParser.scope("100.64.1.1") == "Carrier NAT")
    #expect(NetworkRadarParser.scope("104.18.33.45") == "Public")
    #expect(NetworkRadarParser.scope("::1") == "Loopback")
}
