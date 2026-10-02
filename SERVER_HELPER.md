# TunnelDeck Server Helper

Version: `1.2.0`

Target path: `/usr/local/libexec/tunneldeck-helper`

The helper must be reviewed, copied with SCP, installed as `root:root` mode `0750`, checksum-verified, and health-checked. TunnelDeck must not install or update it without explicit confirmation.

## Commands

- `version` — JSON helper version
- `status`, `health` — wg0 health summary
- `backup OPERATION` — scoped WireGuard/metadata backup
- `list-backups` — backup manifests
- `backup-verify BACKUP_ID` — validate manifest paths and SHA-256
- `restore-preview BACKUP_ID --type wireguard|adguard|antizapret`
- `restore-apply BACKUP_ID --type wireguard|adguard|antizapret --confirm RESTORE`
- `wg-list` — peers with TunnelDeck metadata

Restore never accepts arbitrary source or destination paths. Manifest paths are confined and hash-verified, targets are mapped to typed allowlists, and every apply creates a rollback backup before atomic replacement and service validation.
- `wg-add-peer --name --ip --dns --mtu --allowed-ips --endpoint`
- `wg-remove-peer --public-key [--delete-client] [--allow-existing]`
- `wg-client-config --name` — sensitive output; never log
- `service ACTION UNIT` — only allowlisted units and start/stop/restart

There is no arbitrary exec command. Peer names, IPv4 values, endpoints, AllowedIPs, public keys, MTU, actions and units are validated independently in Swift and Python.
