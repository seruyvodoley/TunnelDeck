import Foundation
import Testing

@testable import TunnelDeck

@Test func homeServiceCatalogLabelsKnownPorts() {
  let labels = HomeServiceCatalog.labels(
    for: Set([22, 445, 5900, 3389])
  )

  #expect(labels.contains("SSH"))
  #expect(labels.contains("SMB"))
  #expect(labels.contains("Screen"))
  #expect(labels.contains("RDP"))
}

@Test func homeInternetPolicyRawValues() {
  #expect(HomeInternetPolicy.vpn.rawValue == "VPN")
  #expect(HomeInternetPolicy.direct.rawValue == "Direct")
  #expect(HomeInternetPolicy.unknown.rawValue == "Unknown")
}

@Test func homeGatewayWakeCommandAcceptsNormalizedMAC() {
  let command = HomeGatewayService.wakeCommand(
    mac: "5C-02-14-88-29-88"
  )

  #expect(command != nil)
  #expect(command?.contains("5c:02:14:88:29:88") == true)
  #expect(command?.contains("etherwake") == true)
}

@Test func homeGatewayWakeCommandRejectsInvalidMAC() {
  #expect(
    HomeGatewayService.wakeCommand(
      mac: "hello; rm -rf /"
    ) == nil
  )
}

@Test func homeProbeSourceExists() {
  #expect(HomeDiscoverySource.probe.rawValue == "probe")
}

@Test func homeServiceCatalogDoesNotTreatMissingProbeAsService() {
  #expect(HomeServiceCatalog.labels(for: []).isEmpty)
}
