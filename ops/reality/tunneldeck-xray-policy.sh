#!/bin/sh
set -eu

# Restore the mark on later packets for locally-originated RU flows.
iptables -t mangle -C OUTPUT \
  -m owner --uid-owner xray \
  -m connmark --mark 0x67 \
  -j CONNMARK --restore-mark 2>/dev/null || \
iptables -t mangle -I OUTPUT 1 \
  -m owner --uid-owner xray \
  -m connmark --mark 0x67 \
  -j CONNMARK --restore-mark

# Mark only new outbound Xray flows whose resolved destination is in td_ru4.
iptables -t mangle -C OUTPUT \
  -m owner --uid-owner xray \
  -m conntrack --ctstate NEW \
  -m set --match-set td_ru4 dst \
  -j MARK --set-mark 0x67 2>/dev/null || \
iptables -t mangle -A OUTPUT \
  -m owner --uid-owner xray \
  -m conntrack --ctstate NEW \
  -m set --match-set td_ru4 dst \
  -j MARK --set-mark 0x67

# Save that mark so every packet in the RU flow keeps table 167 routing.
iptables -t mangle -C OUTPUT \
  -m owner --uid-owner xray \
  -m mark --mark 0x67 \
  -j CONNMARK --save-mark 2>/dev/null || \
iptables -t mangle -A OUTPUT \
  -m owner --uid-owner xray \
  -m mark --mark 0x67 \
  -j CONNMARK --save-mark

# Give the existing homeexit peer the source address it expects.
iptables -t nat -C POSTROUTING \
  -m owner --uid-owner xray -o homeexit \
  -j SNAT --to-source 10.67.0.1 2>/dev/null || \
iptables -t nat -I POSTROUTING 1 \
  -m owner --uid-owner xray -o homeexit \
  -j SNAT --to-source 10.67.0.1
