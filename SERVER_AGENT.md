# TunnelDeck Agent 2.0

`tunneldeck-agent` is a read-only, timer-driven telemetry collector. It is deliberately separate from the privileged remediation helper and continues collecting while the Mac is asleep or TunnelDeck.app is closed.

The default database is `/var/lib/tunneldeck/telemetry.sqlite3`, owned by the dedicated `tunneldeck-agent` account and retained for seven days. Records use UTC wall-clock timestamps and stable identifiers. Agent startup/restart is an `agent-lifecycle` event, never a node outage.

The versioned JSON commands are `agent-version`, `agent-status`, `telemetry-summary`, `telemetry-latest`, `telemetry-samples`, `telemetry-events`, `telemetry-peers`, and `telemetry-adguard`. History commands accept `--since`, `--until`, `--limit`, and incremental `--cursor`.

The systemd timer runs once per minute with no ambient capabilities, a read-only system, protected homes, private temporary/device namespaces, and only `/var/lib/tunneldeck` writable. Four exact sudoers commands provide WireGuard dump, nftables evidence, and two configuration hashes; they cannot mutate configuration or read raw config contents into the database. This narrow sudo boundary is why `NoNewPrivileges` cannot be enabled for the agent service; replacing it with a dedicated read broker is a future hardening option.

Nothing is installed automatically. Deployment requires a separately approved `--apply` invocation.
