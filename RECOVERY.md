# Recovery

## Server component installation rollback

The transactional installer snapshots every Agent binary, unit and sudoers file including existence, content, SHA-256, ownership and mode, plus timer enabled/active and service active state. Candidates are staged on the target filesystem, validated and atomically renamed. Any validation, start or verification failure restores old files and systemd state; files absent before a first install are removed. Agent uninstall preserves `/var/lib/tunneldeck/telemetry.sqlite3` unless `--purge-data` is explicitly supplied.

Helper 2 is installed only at `/usr/local/libexec/tunneldeck-helper2`. Its installation and recovery never modify `/usr/local/libexec/tunneldeck-helper`, the reviewed 1.2.1 recovery path.

## Mac sleep and monitoring gaps

Closing a MacBook pauses local observation; it is not evidence that a VPS went offline. Existing SQLite rows remain available for seven days. On wake TunnelDeck reloads them before making a new check. A gap is rendered as a gap and labelled stale rather than filled with synthetic samples.

When Agent 2.0 is deployed, wake reconciliation imports server samples after the saved cursor before live refresh. If the agent is absent or unreachable, local history is preserved and direct monitoring resumes without treating agent failure as node failure.

The installer defaults to preview. Production install, upgrade, uninstall, helper replacement, and systemd activation require a separately authorized deployment step.

## TunnelDeck 2.0 local data

The SQLite database is local metadata, not a server configuration backup. If unavailable, TunnelDeck recreates the schema and can idempotently re-import retained 1.x Monitoring JSON.

Use **Recovery → Export Diagnostic Bundle** for support. It intentionally excludes SSH private keys, WireGuard `PrivateKey`/`PresharedKey`, passwords, tokens, cookies, Authorization headers, AdGuard credentials and raw client configs.

## VPS unreachable

Keep Write Mode disabled. Verify local routing, known-host status, TCP 22 reachability and the VPS provider console. TunnelDeck never changes network settings automatically.

## wg0 down

Use the provider console or trusted SSH path. Inspect `systemctl status wg-quick@wg0` and `/root/tunneldeck-backups/`. Do not regenerate server keys. Validate a candidate with `wg-quick strip` before applying it.

## Helper broken

Read-only monitoring remains available. Compare the local and server helper SHA-256/version. Remove or replace only `/usr/local/libexec/tunneldeck-helper`; helper failure does not require editing wg0.

## AdGuard broken

Confirm that AntiZapret loopback DNS remains intact. Inspect `AdGuardHome.yaml` and its scoped backup. AdGuard should bind DNS and its web UI to your WireGuard server address, never wildcard/public DNS.

## SSH host key changed

Treat this as critical. Do not bypass host checking. Verify the new fingerprint through the VPS provider console before replacing the known-host entry.

## Restore required

Use Preview Restore to verify `manifest.json`, hashes, typed allowlist and the exact file list. Restore creates a current-state backup, applies atomically and runs the affected service health check. A failed health check triggers rollback. Never copy an entire backup tree over `/`.
