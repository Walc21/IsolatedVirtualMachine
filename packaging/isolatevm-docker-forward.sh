#!/bin/sh
set -eu

bridge=${ISOLATEVM_BRIDGE:-}
chain=DOCKER-USER

case "$bridge" in
  incusbr-*) ;;
  *)
    echo "Configure ISOLATEVM_BRIDGE with the explicit Incus bridge name." >&2
    exit 2
    ;;
esac
case "${bridge#incusbr-}" in
  ''|*[!0-9]*)
    echo "ISOLATEVM_BRIDGE must match incusbr-<numeric-id>." >&2
    exit 2
    ;;
esac

case "${1:-}" in
  start)
    if ! /usr/sbin/iptables -w -C "$chain" -i "$bridge" -j ACCEPT 2>/dev/null; then
      /usr/sbin/iptables -w -I "$chain" 1 -i "$bridge" -j ACCEPT
    fi
    if ! /usr/sbin/iptables -w -C "$chain" -o "$bridge" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
      /usr/sbin/iptables -w -I "$chain" 2 -o "$bridge" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    fi
    ;;
  stop)
    /usr/sbin/iptables -w -D "$chain" -i "$bridge" -j ACCEPT 2>/dev/null || :
    /usr/sbin/iptables -w -D "$chain" -o "$bridge" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || :
    ;;
  *)
    echo "Uso: $0 start|stop (configure ISOLATEVM_BRIDGE)" >&2
    exit 2
    ;;
esac
