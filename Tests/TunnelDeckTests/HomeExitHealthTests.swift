import Foundation
import Testing
@testable import TunnelDeck

private func homeExitOutput(
    link: String = "up",
    lookup: String = "77.88.44.242 dev homeexit table 167 src 10.67.0.1 mark 0x67",
    ruSet: String = "member",
    homeProbe: String = "http=302 connect=0.030 tls=0.100 total=0.180 remote=77.88.44.242",
    fallbackProbe: String = "http=302 connect=0.020 tls=0.080 total=0.120 remote=77.88.44.242",
    handshake: String = "1800000000"
) -> String {
    """
    __TD_HOST__
    primary-vps
    __TD_EPOCH__
    1800000001
    __TD_LINK__
    \(link)
    __TD_HANDSHAKE__
    \(handshake)
    __TD_TRANSFER__
    12345 67890
    __TD_RULES__
    1067: from all fwmark 0x67 lookup 167
    __TD_RU_TABLE__
    default dev homeexit scope link
    __TD_RU_LOOKUP__
    \(lookup)
    __TD_RU_SET__
    \(ruSet)
    __TD_DNS__
    77.88.44.242
    __TD_HOMEEXIT_DATA__
    \(homeProbe)
    __TD_VPS_FALLBACK_DATA__
    \(fallbackProbe)
    __TD_TRANSFER_AFTER__
    12345 67890
    """
}

@Test func homeExitHealthRequiresRealPinnedDataPlaneInAdditionToHandshake() {
    let now = Date(timeIntervalSince1970: 1_800_000_001)
    let snapshot = HomeExitHealthSnapshot.parse(homeExitOutput(), succeeded: true, now: now)
    #expect(snapshot.state == .online)
    #expect(snapshot.routeCorrect == true)
    #expect(snapshot.ruAddressSetContainsProbe == true)
    #expect(snapshot.homeExitDataPassed == true)
    #expect(snapshot.homeExitHTTPStatus == 302)
    #expect(snapshot.vpsFallbackDataPassed == true)
    #expect(snapshot.receivedBytes == 12345)

    let failedData = HomeExitHealthSnapshot.parse(
        homeExitOutput(homeProbe: "curl: (28) Operation timed out"),
        succeeded: true,
        now: now
    )
    #expect(failedData.state == .warning)
    #expect(failedData.homeExitDataPassed == false)
    #expect(failedData.handshakeAgeSeconds == 1)
}

@Test func homeExitHealthNeedsConsecutiveDataFailuresBeforeOfflineAndOnlyRecommendsFallback() {
    let now = Date(timeIntervalSince1970: 1_800_000_600)
    let previous = (1...2).map { offset in
        HomeExitHealthSample(
            host: "primary-vps", checkedAt: now.addingTimeInterval(TimeInterval(-offset * 180)),
            interfaceUp: true, routeCorrect: true, homeExitDataOK: false,
            vpsFallbackDataOK: true, handshakeAgeSeconds: 20,
            reason: "Pinned homeexit data probe failed"
        )
    }
    let snapshot = HomeExitHealthSnapshot.parse(
        homeExitOutput(homeProbe: "curl: (28) Operation timed out"),
        succeeded: true, history: previous, now: now
    )
    #expect(snapshot.state == .offline)
    #expect(snapshot.consecutiveFailures == 3)
    #expect(snapshot.recommendation == .vpsFallbackAvailable)
    #expect(snapshot.automaticRouteChangesEnabled == false)
}

@Test func homeExitHealthRejectsBadPolicyRouteAndMissingEvidence() {
    let now = Date(timeIntervalSince1970: 1_800_000_001)
    let wrongRoute = HomeExitHealthSnapshot.parse(
        homeExitOutput(lookup: "77.88.44.242 dev ens3 table main"),
        succeeded: true, now: now
    )
    #expect(wrongRoute.state == .warning)
    #expect(wrongRoute.routeCorrect == false)
    #expect(wrongRoute.reason.contains("table 167"))

    let noSSH = HomeExitHealthSnapshot.parse("", succeeded: false, now: now)
    #expect(noSSH.state == .unknown)
    #expect(noSSH.homeExitDataPassed == nil)
}

@Test func homeExitReadCommandIsAllowlistedAndContainsNoNetworkMutations() throws {
    let command = ReadOnlyCommandPolicy.authorize(.homeExitHealthVPS)
    #expect(command.contains("curl -4 --interface homeexit"))
    #expect(command.contains("curl -4 --interface ens3"))
    #expect(command.contains("iif wg0 mark 0x67"))
    #expect(command.contains("table 167"))
    #expect(command.contains("__TD_TRANSFER_AFTER__"))
    #expect(!command.contains("ip route add"))
    #expect(!command.contains("ip route replace"))
    #expect(!command.contains("ip route del"))
    #expect(!command.contains("systemctl restart"))
    #expect(!command.contains("iptables -"))
    #expect(!command.contains("nft add"))
    #expect(throws: CommandPolicyError.deniedCommand) {
        try ReadOnlyCommandPolicy.authorize(rawCommand: "ip route replace default dev ens3")
    }
}

@Test func homeExitRecoveryNeedsThreeSpacedSuccesses() {
    let start = Date(timeIntervalSince1970: 1_800_000_000)
    let samples = [
        HomeExitHealthSample(host: "primary-vps", checkedAt: start, interfaceUp: true, routeCorrect: true, homeExitDataOK: false, vpsFallbackDataOK: true, handshakeAgeSeconds: 600, reason: "failure"),
        HomeExitHealthSample(host: "primary-vps", checkedAt: start.addingTimeInterval(180), interfaceUp: true, routeCorrect: true, homeExitDataOK: true, vpsFallbackDataOK: true, handshakeAgeSeconds: 3, reason: "success"),
        HomeExitHealthSample(host: "primary-vps", checkedAt: start.addingTimeInterval(360), interfaceUp: true, routeCorrect: true, homeExitDataOK: true, vpsFallbackDataOK: true, handshakeAgeSeconds: 2, reason: "success"),
        HomeExitHealthSample(host: "primary-vps", checkedAt: start.addingTimeInterval(540), interfaceUp: true, routeCorrect: true, homeExitDataOK: true, vpsFallbackDataOK: true, handshakeAgeSeconds: 1, reason: "success")
    ]
    let decision = HomeExitResiliencePolicy.evaluate(history: samples, now: start.addingTimeInterval(540))
    #expect(decision.recommendation == .homeExitRecovered)
}
