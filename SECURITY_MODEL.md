# TunnelDeck Security Model

```text
TunnelDeck.app
  └─ strict SSH transport and host verification
      ├─ sudo -u tunneldeck-agent → tunneldeck-agent (read-only telemetry)
      ├─ tunneldeck-helper 1.2.1 (stable legacy operations)
      └─ tunneldeck-helper2 2.0 (new explicit transactions)
```

The agent never persists WireGuard private keys, preshared keys, passwords, tokens, cookies, authorization headers, or raw secret values. Peer public identifiers and configuration hashes are allowed structural data. Its database is not a credential store.

The helper is not a daemon and exposes no arbitrary execution primitive. Backups use a controlled directory, manifests are SHA-256 verified, traversal and symlinks are rejected, and failed validation rolls back. SSH/firewall apply requires independent access verification and must preserve the active management path.

The management account is explicit and strictly validated. Its root-owned mode-`0440` sudoers fragment permits only the Agent read API under the dedicated Agent identity. A separate fragment permits the Agent's four exact privileged evidence reads. Neither grants `collect`, a shell, an alternate executable path, or direct telemetry database access.

The macOS SQLite database stores node-scoped operational history, events, alert state, baselines, peer counters, and AdGuard counters. SSH paths and AdGuard credentials remain in secure storage. Stale observations are not interpreted as offline checks.
