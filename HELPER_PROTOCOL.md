# TunnelDeck Helper Protocol 2

The helpers are deliberately side-by-side. `/usr/local/libexec/tunneldeck-helper` remains the stable 1.2.1 implementation for existing peer, backup, restore, health and service operations. `/usr/local/libexec/tunneldeck-helper2` exposes protocol 2 only. Installing or removing Helper 2 never replaces the legacy path.

Helper 2 `helper-info` returns `version`, `protocolVersion`, and explicit capabilities. TunnelDeck negotiates legacy and protocol-2 capabilities independently; protocol 2 never grants `legacy-safe-writes`. Absence of Helper 2 is an optional unavailable state, not a failure of Helper 1.2.1.

TunnelDeck Agent and Helper remain version 2.0.0 in the TunnelDeck 2.0.1 app release; pagination changes only how the existing cursor API is consumed and do not change the server protocol.

Every protocol-2 mutation follows preview, validation, backup, apply, post-check, and success. A failure triggers rollback and rollback validation. JSON results contain `operationID`, `operation`, `preview`, `backup`, `changedFiles`, `preChecks`, `postChecks`, `result`, `rollbackStatus`, and `warnings`.

There is no arbitrary shell or arbitrary-path operation. Units, identifiers, interfaces, networks, backup children, and manifests are allowlisted or strictly validated. SSH and firewall changes remain preview-only until independently verified access and rescue adapters are deployed.

Exit code 0 means preview/success, 2 validation rejection, 3 apply/runtime failure with successful rollback, and 4 rollback failure. A structured `"result":"failed"` response is never paired with exit 0. Stdout is JSON; stderr is diagnostic only.
