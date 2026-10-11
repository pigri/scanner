#!/usr/bin/env bash
# Recreate the 'scanvpn' network namespace + wgscan WireGuard interface so the
# foreign-egress scan workers (scan-worker@) leave via the Windscribe tunnel and
# never the host IP. This is the foreign twin of scanvpn-netns-hu.sh; the two
# namespaces are independent and the fleet is split by target suffix (see
# scan-worker@.service / scan-worker-hu@.service).
#
# WireGuard is namespace-aware: we create wgscan in the INIT netns (so its
# encrypted UDP transport socket egresses via the host's real network to reach
# the endpoint) and then move ONLY the inner interface into the scanvpn netns.
# Everything a scan does is confined to scanvpn, whose sole default route is
# wgscan -- so even a dead tunnel fails closed rather than leaking the host IP.
#
# WHY THE HARDENING: the netns's only resolver is the in-tunnel DNS (see $CONF's
# DNS=), reachable ONLY through wgscan. So a present-but-dead tunnel doesn't just
# stop scans -- every in-namespace lookup fails "Could not resolve host", which
# silently breaks the CT mirror (ct-mirror.service) and the daily recon refresh
# (scan-feed) with no error at the systemd level. The check() gate below makes
# the unit fail closed on a dead tunnel so that failure can't go unnoticed.
#
# NOTE: WireGuard is UDP-only. If the tunnel never completes a handshake (wg show
# => "latest handshake" absent, 0 B received) while TCP egress still works, the
# usual cause is the host firewall dropping the UDP *return* traffic, not a bad
# config. On the Hetzner stateless firewall that means a missing inbound rule for
# "udp, source port 443" — see deploy/README.md.
set -euo pipefail

NS=scanvpn
IF=wgscan
CONF=/etc/wireguard/scanvpn.conf
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
  # If a prior run failed after creating wgscan but before moving it, the iface
  # lingers in the init netns -- clean that up too.
  ip link del "$IF" 2>/dev/null || true
}

up() {
  [ -r "$CONF" ] || { echo "scanvpn-netns: $CONF not readable" >&2; exit 1; }
  local addrs dns has_v6=0 has_v4=0
  addrs=$(read_conf_field Address | tr ',' ' ')
  dns=$(read_conf_field DNS | tr ',' ' ')
  [ -n "$addrs" ] || { echo "scanvpn-netns: no Address in $CONF" >&2; exit 1; }

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
    echo "scanvpn-netns: WARNING: no DNS in $CONF; in-namespace name resolution will not work" >&2
  fi
}

# Verify the tunnel actually handshakes, for use as the unit's ExecStartPost. The
# netns-presence guard in scan-worker@.service only proves the namespace exists,
# not that egress works — so a present-but-dead tunnel (e.g. the host firewall
# dropping UDP return traffic) would let workers drain the queue through a black
# hole and mark targets done with no findings, and would silently freeze the CT
# mirror and recon refresh on DNS failures. By gating here, a dead tunnel means
# the netns is torn down, so the workers' presence guard keeps them out until the
# tunnel is genuinely up. On failure check() runs down() itself (prompt, and
# independent of systemd semantics); the unit's ExecStopPost=down is the backstop.
# NOTE: cleanup must not hang off ExecStop= — a Type=oneshot unit whose
# ExecStartPost fails goes straight to "failed" without ever being "active", and
# systemd skips ExecStop= in that case (only ExecStopPost= runs unconditionally).
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
    # First peer only: the Windscribe conf is single-peer. `|| true` so a transient
    # `wg show` error is retried like a missing handshake, not treated as fatal
    # (pipefail would otherwise abort the whole retry loop on one hiccup).
    hs=$(ip netns exec "$NS" wg show "$IF" latest-handshakes 2>/dev/null | awk '{print $2; exit}') || true
    now=$(date +%s)
    if [ -n "$hs" ] && [ "$hs" -gt 0 ] && [ "$(( now - hs ))" -lt 180 ]; then
      return 0
    fi
    sleep 2
  done
  echo "scanvpn-netns: $IF has no recent WireGuard handshake — tunnel is not passing traffic." >&2
  echo "scanvpn-netns: WireGuard is UDP-only; check the host firewall allows inbound udp src-port 443 (see deploy/README.md)." >&2
  down   # tear the dead tunnel down ourselves so the stale netns can't linger and
         # fool scan-worker@'s presence-only guard into draining the queue.
  return 1
}

case "${1:-up}" in
  up)    up ;;
  check) check ;;
  down)  down ;;
  *)     echo "usage: $0 {up|check|down}" >&2; exit 1 ;;
esac
