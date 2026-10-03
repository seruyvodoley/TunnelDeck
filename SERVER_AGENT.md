# TunnelDeck Agent 2.0

`tunneldeck-agent` is a read-only, timer-driven telemetry collector. It is deliberately separate from the privileged remediation helper and continues collecting while the Mac is asleep or TunnelDeck.app is closed.

The default database is `/var/lib/tunneldeck/telemetry.sqlite3`, owned by the dedicated `tunneldeck-agent` account and retained for seven days. Records use UTC wall-clock timestamps and stable identifiers. Agent startup/restart is an `agent-lifecycle` event, never a node outage.

The versioned JSON commands are `agent-version`, `agent-status`, `telemetry-summary`, `telemetry-latest`, `telemetry-samples`, `telemetry-events`, `telemetry-peers`, and `telemetry-adguard`. History commands accept `--since`, `--until`, `--limit`, and incremental `--cursor`.

## Cursor contract

Each stream uses its SQLite `rowid` as a strictly increasing cursor. A request returns rows where `rowid > cursor`, ordered by `rowid`; `nextCursor` is the last row actually returned. The next request therefore neither repeats nor skips a successful page. An empty page ends catch-up. A non-empty page with an unchanged or decreasing cursor is rejected by the app.

TunnelDeck persists every decoded page before checkpointing that stream's cursor. A malformed page, cancellation, transport error, or local persistence error leaves its cursor at the preceding completed page. A replay is safe because local tables use stable IDs with `INSERT OR IGNORE`. Samples, events, peers, and AdGuard statistics have independent cursors.

The app requests 2,000 rows per page and bounds one synchronization to 16 pages and 25,000 records per stream. If the cap is reached, completed progress remains checkpointed and the next synchronization resumes from that cursor. Launch and wake run immediate catch-up; normal operation schedules at most one catch-up approximately once per minute, independently of faster live polling.

The systemd timer runs once per minute with no ambient capabilities, a read-only system, protected homes, private temporary/device namespaces, and only `/var/lib/tunneldeck` writable. Four exact sudoers commands provide WireGuard dump, nftables evidence, and two configuration hashes; they cannot mutate configuration or read raw config contents into the database. This narrow sudo boundary is why `NoNewPrivileges` cannot be enabled for the agent service; replacing it with a dedicated read broker is a future hardening option.

The telemetry database and directory remain owned by `tunneldeck-agent` with directory mode `0750`; the management SSH account never receives filesystem access. TunnelDeck invokes only the read API as `sudo -n -u tunneldeck-agent /usr/local/libexec/tunneldeck-agent <command>`. Installation renders a management-user-specific sudoers fragment after strict username and `visudo -cf` validation. Exact rules cover status/summary commands and anchored argument regular expressions cover paginated history. `collect`, alternate binary paths, arbitrary arguments and shells are not allowed.

Nothing is installed automatically. Deployment requires a separately approved `--apply` invocation.
