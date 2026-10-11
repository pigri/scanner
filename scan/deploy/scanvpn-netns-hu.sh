#!/usr/bin/env bash
# Recreate the 'scanvpn-hu' network namespace + wgscan-hu WireGuard interface so
# the HU-egress scan workers (scan-worker-hu@) leave via the Windscribe HU
# tunnel and never the host IP. This is the HU twin of scanvpn-netns.sh; the two
# namespaces are independent and the fleet is split by target suffix (see
# scan-worker-hu@.service / scan-worker@.service).
#
# WHY THIS EXISTS: the "Split scan-worker fleet by target country" change added
# scan-worker-hu@.service, whose ExecStartPre fails closed until the 'scanvpn-hu'
# netns is present — but shipped no unit to create that netns. With it missing,
# the HU workers loop forever in start-pre and every .gov.hu / .hu target sits
# unclaimed in scan_queue. This script + scanvpn-netns-hu.service close that gap.
#
# WireGuard is namespace-aware: we create wgscan-hu in the INIT netns (so its
# encrypted UDP transport socket egresses via the host's real network to reach
# the endpoint) and then move ONLY the inner interface into the scanvpn-hu netns.
# Everything a scan does is confined to scanvpn-hu, whose sole default route is
# wgscan-hu -- so even a dead tunnel fails closed rather than leaking the host IP.
#
# NOTE: WireGuard is UDP-only. If the tunnel never completes a handshake (wg show
# => "latest handshake" absent, 0 B received) while TCP egress still works, the
# usual cause is the host firewall dropping the UDP *return* traffic, not a bad
# config. On the Hetzner stateless firewall that means a missing inbound rule for
# "udp, source port 443" — see deploy/README.md.
set -euo pipefail

NS=scanvpn-hu
IF=wgscan-hu
CONF=/etc/wireguard/scanvpn-hu.conf
MTU=1320   # Windscribe WireGuard MTU; not carried in the .conf, so set here.

# Address(es) and DNS are read straight from $CONF so this script never carries a
# per-key assignment (the keys rotate, and the repo is public). wg-quick strip
# removes [Interface] Address/DNS before `wg setconf`, so we re-apply them here.
read_conf_field() {   # field name -> comma-separated value from [Interface]
  awk -F= -v f="$1" '
    tolower($1) ~ "^[[:space:]]*"tolower(f)"[[:space:]]*$" {
      sub(/^[^=]*=/, ""); sub(/#.*/, ""); gsub(/[[:space:]]/, ""); print; exit }' "$CONF"
}

down() {
  ip netns del "$NS" 2>/dev/null || true
  # If a prior run failed after creating wgscan-hu but before moving it, the
  # iface lingers in the init netns -- clean that up too.
  ip link del "$IF" 2>/dev/null || true
}

up() {
  [ -r "$CONF" ] || { echo "scanvpn-netns-hu: $CONF not readable" >&2; exit 1; }
  local addrs dns has_v6=0 has_v4=0
  addrs=$(read_conf_field Address | tr ',' ' ')
  dns=$(read_conf_field DNS | tr ',' ' ')
  [ -n "$addrs" ] || { echo "scanvpn-netns-hu: no Address in $CONF" >&2; exit 1; }

  down                                   # idempotent: clear any stale state first
  ip netns add "$NS"
  ip link add "$IF" type wireguard
  wg setconf "$IF" <(wg-quick strip "$CONF")   # PrivateKey/Peer/PSK/Endpoint/keepalive
  ip link set "$IF" netns "$NS"                 # move inner iface; UDP socket stays in init netns
  ip -n "$NS" link set "$IF" mtu "$MTU"
  for a in $addrs; do
    ip -n "$NS" addr add "$a" dev "$IF"
    case "$a" in *:*) has_v6=1 ;; *) has_v4=1 ;; esac
  done
  ip -n "$NS" link set "$IF" up
  if [ "$has_v4" -eq 1 ]; then ip -n "$NS" route add default dev "$IF"; fi
  if [ "$has_v6" -eq 1 ]; then ip -n "$NS" -6 route add default dev "$IF"; fi
  # ip netns exec bind-mounts this over /etc/resolv.conf for anything run in the ns.
  # Without a nameserver here every in-ns lookup fails silently, so if the conf
  # carried no DNS, warn loudly and leave any existing resolv.conf untouched
  # rather than truncating it to an empty (resolution-dead) file.
  if [ -n "$dns" ]; then
    install -d -m 0755 /etc/netns/"$NS"
    : > /etc/netns/"$NS"/resolv.conf
    for d in $dns; do printf 'nameserver %s\n' "$d" >> /etc/netns/"$NS"/resolv.conf; done
  else
    echo "scanvpn-netns-hu: WARNING: no DNS in $CONF; in-namespace name resolution will not work" >&2
  fi
}

# Verify the tunnel actually handshakes, for use as the unit's ExecStartPost. The
# netns-presence guard in scan-worker-hu@.service only proves the namespace
# exists, not that egress works — so a present-but-dead tunnel (e.g. the host
# firewall dropping UDP return traffic) would let workers drain the queue through
# a black hole and mark targets done with no findings. By gating here, a failed
# check fails this oneshot unit, its ExecStop runs down(), the netns disappears,
# and the workers' presence guard keeps them out until the tunnel is genuinely up.
#
# WireGuard is lazy without PersistentKeepalive: it won't handshake until a packet
# needs sending. So we provoke one (a ping into the tunnel; its success is
# irrelevant) and then poll wg's last-handshake timestamp. Setting
# "PersistentKeepalive = 25" in the .conf makes the tunnel self-maintain and this
# probe a near-instant confirmation instead of the trigger.
check() {
  local dns probe hs now
  dns=$(read_conf_field DNS | tr ',' ' ' | awk '{print $1}')
  probe=${dns:-1.1.1.1}   # a routed-through-the-tunnel target to provoke a handshake
  for _ in $(seq 8); do
    ip netns exec "$NS" ping -c1 -W2 "$probe" >/dev/null 2>&1 || true
    hs=$(ip netns exec "$NS" wg show "$IF" latest-handshakes 2>/dev/null | awk '{print $2; exit}')
    now=$(date +%s)
    if [ -n "$hs" ] && [ "$hs" -gt 0 ] && [ "$(( now - hs ))" -lt 180 ]; then
      return 0
    fi
    sleep 2
  done
  echo "scanvpn-netns-hu: $IF has no recent WireGuard handshake — tunnel is not passing traffic." >&2
  echo "scanvpn-netns-hu: WireGuard is UDP-only; check the host firewall allows inbound udp src-port 443 (see deploy/README.md)." >&2
  return 1
}

case "${1:-up}" in
  up)    up ;;
  check) check ;;
  down)  down ;;
  *)     echo "usage: $0 {up|check|down}" >&2; exit 1 ;;
esac
