# Recovery

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
