# TunnelDeck Server Helper

Version: `1.0.0`

Target path: `/usr/local/libexec/tunneldeck-helper`

The helper must be reviewed, copied with SCP, installed as `root:root` mode `0750`, checksum-verified, and health-checked. TunnelDeck must not install or update it without explicit confirmation.

## Commands

- `version` — JSON helper version
- `status`, `health` — wg0 health summary
- `backup OPERATION` — scoped WireGuard/metadata backup
- `list-backups` — backup manifests
- `wg-list` — peers with TunnelDeck metadata
- `wg-add-peer --name --ip --dns --mtu --allowed-ips --endpoint`
- `wg-remove-peer --public-key [--delete-client] [--allow-existing]`
- `wg-client-config --name` — sensitive output; never log
- `service ACTION UNIT` — only allowlisted units and start/stop/restart

There is no arbitrary exec command. Peer names, IPv4 values, endpoints, AllowedIPs, public keys, MTU, actions and units are validated independently in Swift and Python.
