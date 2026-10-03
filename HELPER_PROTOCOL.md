# TunnelDeck Helper Protocol 2

`helper-info` returns `version`, `protocolVersion`, and explicit capabilities. TunnelDeck recognizes helper 1.2.1 as protocol 1 with `legacy-safe-writes`; it does not infer 2.x write support from a version string.

Every protocol-2 mutation follows preview, validation, backup, apply, post-check, and success. A failure triggers rollback and rollback validation. JSON results contain `operationID`, `operation`, `preview`, `backup`, `changedFiles`, `preChecks`, `postChecks`, `result`, `rollbackStatus`, and `warnings`.

There is no arbitrary shell or arbitrary-path operation. Units, identifiers, interfaces, networks, backup children, and manifests are allowlisted or strictly validated. SSH and firewall changes remain preview-only until independently verified access and rescue adapters are deployed.

Exit code 0 means a valid preview/success response, 2 means validation rejection, and other nonzero codes are execution failures. Stdout is JSON; stderr is diagnostic only.
