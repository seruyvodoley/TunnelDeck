# VLESS + REALITY rollback

The pre-change host/network snapshot is root-only at:

`/root/tunneldeck-backups/reality-20261021-1520`

It includes `iptables-save`, `ip6tables-save`, `ipset save`, routes/rules, original TunnelDeck firewall and RU-route scripts/units, and the warning-level Xray config used for this deployment. Do not apply the full `iptables.v4` snapshot with `iptables-restore` on a live host; that would replace unrelated firewall changes made since the snapshot.

## Remove only the secondary XHTTP transport

The additive XHTTP deployment has its own root-only snapshot and rollback script at `/root/tunneldeck-backups/reality-20261023-xhttp`. To remove only that fallback while preserving the original 8443 Xray service, policy rules, tunnels, and Caddy:

```sh
/root/tunneldeck-backups/reality-20261023-xhttp/rollback-xhttp.sh
```

The Caddy TLS-fronted XHTTP path has a separate root-only snapshot and rollback script at `/root/tunneldeck-backups/reality-20261023-caddy-xhttp`. To remove only the TCP/443 XHTTP path and its loopback-only service:

```sh
/root/tunneldeck-backups/reality-20261023-caddy-xhttp/rollback-caddy-xhttp.sh
```

This restores the saved Caddyfile and gracefully reloads the existing Caddy container, then removes only `tunneldeck-xray-xhttp-tls.service` and `/usr/local/etc/xray/xhttp-tls.json`. It does not change Caddy port 443, its webhook path, the 8443 or 2053 Xray services, firewall rules, tunnels, or routing policy.

The script stops and disables only `tunneldeck-xray-xhttp.service`, removes only the TCP/2053 firewall allow and matching persistent firewall line, and deletes only its unit, config, and separate Xray binary. It does not touch `xray.service`, the 8443 listener, Xray policy, `wg0`, `homeexit`, `awgtd0`, `awgfriend0`, route tables, or Caddy. Device profiles remain in the protected backup directory so they can be revoked or restored separately.

To remove only the REALITY additions while keeping WireGuard, AmneziaWG, Caddy, and existing route rules in place:

```sh
systemctl disable --now xray.service tunneldeck-xray-policy.service

iptables -t mangle -D OUTPUT -m owner --uid-owner xray -m connmark --mark 0x67 -j CONNMARK --restore-mark
iptables -t mangle -D OUTPUT -m owner --uid-owner xray -m conntrack --ctstate NEW -m set --match-set td_ru4 dst -j MARK --set-mark 0x67
iptables -t mangle -D OUTPUT -m owner --uid-owner xray -m mark --mark 0x67 -j CONNMARK --save-mark
iptables -t nat -D POSTROUTING -m owner --uid-owner xray -o homeexit -j SNAT --to-source 10.67.0.1
iptables -D TUNNELDECK_INPUT -i ens3 -d 91.196.32.58/32 -p tcp --dport 8443 -m conntrack --ctstate NEW -m comment --comment tunneldeck-xray-reality -j ACCEPT

install -o root -g root -m 0700 /root/tunneldeck-backups/reality-20261021-1520/tunneldeck-firewall /usr/local/sbin/tunneldeck-firewall
rm -f /etc/systemd/system/xray.service /etc/systemd/system/tunneldeck-xray-policy.service
rm -f /usr/local/sbin/tunneldeck-xray-policy
rm -f /etc/systemd/system/tunneldeck-ru-route.service.d/override.conf
systemctl daemon-reload
rm -rf /usr/local/etc/xray
rm -f /usr/local/bin/xray
userdel xray
groupdel xray
```

Removing the RU-route override restores the original timer behavior too. Keeping the override is preferable if the RU set should continue refreshing every 12 hours.

The local protected client profiles are under `~/.config/tunneldeck/reality/`; delete that directory separately when device credentials should be revoked. If rolling back only one device, remove its UUID from the server config and restart Xray rather than deleting the whole service.

After rollback, check `systemctl is-active wg-quick@wg0 wg-quick@homeexit tunneldeck-awgtd0.service tunneldeck-firewall.service`, confirm Caddy still listens on TCP/443, and confirm `ip rule show` still contains the existing mark-`0x67` rule to table `167`. No tunnel needs to be stopped during this rollback.
