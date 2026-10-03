import Foundation

/// Owns protocol-2 remediation discovery without granting legacy write authority.
actor RemediationController {
    private let helper2: Helper2Service
    init(helper2: Helper2Service) { self.helper2 = helper2 }

    func capabilities(configuration: SSHConfiguration) async -> Helper2Capabilities? {
        guard let capabilities = await helper2.capabilities(configuration: configuration),
              capabilities.protocolVersion == 2,
              capabilities.supports("transaction-v2") else { return nil }
        return capabilities
    }
}
