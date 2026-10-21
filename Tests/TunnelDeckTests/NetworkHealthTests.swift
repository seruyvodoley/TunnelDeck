import Foundation
import Testing
@testable import TunnelDeck

@Test func networkHealthSeparatesReachabilityFromRouteLookupEvidence() {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let output = """
    __TD_HOST__
    primary-vps
    __TD_ROUTE_MAIN__
    1.1.1.1 via 10.0.0.1 dev ens3 src 91.196.32.58
    __TD_ROUTE_RU_MARK__
    77.88.8.8 dev homeexit table 167 src 10.67.0.1 mark 0x67
    __TD_DNS__
    93.184.216.34 STREAM example.com
    __TD_HTTPS__
    http=200 connect=0.020 tls=0.080 total=0.130 ip=93.184.216.34
    __TD_XRAY__
    LoadState=loaded
    ActiveState=active
    SubState=running
    __TD_XRAY_LISTENER__
    LISTEN 0 4096 *:8443
    __TD_CADDY_CONTAINER__
    running|unless-stopped
    __TD_RESOURCES__
    memory_available_bytes=1000
    disk_available_bytes=2000 disk_used_percent=42%
    """

    let snapshot = NetworkHealthSnapshot.parse(output, succeeded: true, now: now)
    #expect(snapshot.host == "primary-vps")
    #expect(snapshot.checkedAt == now)
    #expect(snapshot.probes.first(where: { $0.id == "main-route" })?.state == .passed)
    #expect(snapshot.probes.first(where: { $0.id == "ru-policy" })?.state == .passed)
    #expect(snapshot.probes.first(where: { $0.id == "https" })?.state == .passed)
    #expect(snapshot.probes.first(where: { $0.id == "xray" })?.state == .passed)
    #expect(snapshot.probes.first(where: { $0.id == "caddy" })?.state == .passed)
    #expect(snapshot.probes.first(where: { $0.id == "resources" })?.state == .warning)
    #expect(snapshot.probes.first(where: { $0.id == "xray" })?.detail.contains("does not prove a client REALITY session") == true)
    #expect(snapshot.probes.first(where: { $0.id == "ru-policy" })?.detail.contains("no packet injected") == true)
}

@Test func networkHealthDoesNotCallFailedHttpsOrMissingRouteHealthy() {
    let output = """
    __TD_ROUTE_MAIN__
    Network is unreachable
    __TD_ROUTE_RU_MARK__
    RTNETLINK answers: Network is unreachable
    __TD_DNS__
    Temporary failure in name resolution
    __TD_HTTPS__
    curl: (6) Could not resolve host
    __TD_XRAY__
    ActiveState=inactive
    SubState=dead
    __TD_XRAY_LISTENER__
    __TD_CADDY_CONTAINER__
    exited|unless-stopped
    """
    let snapshot = NetworkHealthSnapshot.parse(output, succeeded: true)
    #expect(snapshot.probes.first(where: { $0.id == "main-route" })?.state == .warning)
    #expect(snapshot.probes.first(where: { $0.id == "ru-policy" })?.state == .warning)
    #expect(snapshot.probes.first(where: { $0.id == "dns" })?.state == .failed)
    #expect(snapshot.probes.first(where: { $0.id == "https" })?.state == .failed)
    #expect(snapshot.probes.first(where: { $0.id == "xray" })?.state == .warning)
    #expect(snapshot.probes.first(where: { $0.id == "caddy" })?.state == .warning)
}

@Test func networkHealthSSHFailureIsExplicitAndUnknownEvidenceIsNotGreen() {
    let snapshot = NetworkHealthSnapshot.parse("", succeeded: false)
    #expect(snapshot.probes.count == 1)
    #expect(snapshot.probes[0].state == .failed)
}
