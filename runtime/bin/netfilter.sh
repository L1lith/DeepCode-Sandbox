#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Deepsand egress policy.
#
# Applied by entrypoint.sh as root, before privileges are dropped. Because the
# rules live in the container's own network namespace and the sandbox process
# cannot run iptables after setpriv drops every capability, the contained
# DeepCode instance cannot undo them.
#
# Modes
#   none        - DNS and the model API only. No proxy: the client does not use
#                 one, so the endpoint is allowed by address instead.
#   internet    - public internet reachable, host + LAN + link-local blocked
#   allowlisted - DNS, the model API, the operator's named addresses and the
#                 Deepsand egress allowlist proxy are reachable, nothing else.
#                 `restricted` is the same mode under its old name, still accepted
#                 so that an image built before the rename keeps working.
#   full        - not called; unrestricted egress (operator's explicit choice)
#
# Environment
#   DEEPSAND_PROXY_ADDR / DEEPSAND_PROXY_HOST / DEEPSAND_PROXY_PORT
#   DEEPSAND_MODEL_ADDRS    - comma-separated `ip:port`, the model endpoint(s)
#   DEEPSAND_ALLOW_ADDRS    - comma-separated `ip[:port]`, the addresses the
#                             operator named in the allowlist. Omitted port means
#                             every port. These are reached *directly*, because a
#                             database or an SSH endpoint cannot speak HTTP to a
#                             proxy; hostname entries are proxy-only by design.
#   DEEPSAND_PUBLISHED_PORTS - comma-separated ports published on the host, so a
#                             server the sandbox runs is reachable from outside
#
# Exit code 1 means the policy could not be applied. entrypoint.sh treats that
# as fatal unless DEEPSAND_NETFILTER_OPTIONAL=1.
# ---------------------------------------------------------------------------
set -uo pipefail

MODE="${1:-internet}"
PROXY_ADDR="${DEEPSAND_PROXY_ADDR:-}"
PROXY_HOST="${DEEPSAND_PROXY_HOST:-deepsand-proxy}"
PROXY_PORT="${DEEPSAND_PROXY_PORT:-}"

log() { printf '[deepsand-netfilter] %s\n' "$*" >&2; }

case "$MODE" in
  internet|allowlisted|restricted|none) ;;
  any) ;;
  *)
    log "mode '$MODE' needs no policy"
    exit 0
    ;;
esac

# The old spelling is folded onto the new one so every branch below reads the same.
if [ "$MODE" = "restricted" ]; then
  log "mode 'restricted' is the old name for 'allowlisted'; treating it as such"
  MODE="allowlisted"
fi

# --- pick an iptables frontend ---------------------------------------------
IPT=""
for cand in iptables iptables-legacy iptables-nft; do
  if command -v "$cand" >/dev/null 2>&1; then IPT="$cand"; break; fi
done
if [ -z "$IPT" ]; then
  log "no iptables binary available"
  exit 1
fi
log "using $IPT for mode '$MODE'"

REJECT_OPT=""
if "$IPT" -A OUTPUT -d 203.0.113.254 -j REJECT --reject-with icmp-admin-prohibited >/dev/null 2>&1; then
  REJECT_OPT="--reject-with icmp-admin-prohibited"
  "$IPT" -D OUTPUT -d 203.0.113.254 -j REJECT >/dev/null 2>&1 || true
fi

reject_all() { # $1 = table command prefix is implicit
  if [ -n "$REJECT_OPT" ]; then
    "$IPT" -A OUTPUT -j REJECT $REJECT_OPT
  else
    "$IPT" -A OUTPUT -j REJECT
  fi
}

# --- reset the filter table ------------------------------------------------
"$IPT" -F OUTPUT || { log "cannot flush OUTPUT chain"; exit 1; }
"$IPT" -P OUTPUT ACCEPT

# --- always allow: loopback + replies to our own outbound connections -------
"$IPT" -A OUTPUT -o lo -j ACCEPT || exit 1
"$IPT" -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || {
  log "conntrack match unavailable"
  exit 1
}

# --- always allow: DNS to the resolvers this container was configured with ---
DNS_ALLOWED=0
if [ -r /etc/resolv.conf ]; then
  while read -r ns; do
    [ -n "$ns" ] || continue
    case "$ns" in
      *:*) continue ;;   # IPv4 policy only; IPv6 is handled separately below
    esac
    "$IPT" -A OUTPUT -d "$ns" -p udp --dport 53 -j ACCEPT && DNS_ALLOWED=1
    "$IPT" -A OUTPUT -d "$ns" -p tcp --dport 53 -j ACCEPT && DNS_ALLOWED=1
  done < <(awk '/^[[:space:]]*nameserver/ {print $2}' /etc/resolv.conf | sort -u)
fi
# Docker's embedded resolver always lives at 127.0.0.11, reached over lo, but
# name it explicitly so a hostile /etc/resolv.conf cannot point us at the host.
"$IPT" -A OUTPUT -d 127.0.0.11 -p udp --dport 53 -j ACCEPT 2>/dev/null && DNS_ALLOWED=1
"$IPT" -A OUTPUT -d 127.0.0.11 -p tcp --dport 53 -j ACCEPT 2>/dev/null && DNS_ALLOWED=1
log "dns exemptions installed: $DNS_ALLOWED"

if [ "$MODE" = "allowlisted" ] || [ "$MODE" = "none" ]; then
  # --- the model API, by address -------------------------------------------
  #
  # This is the one destination that has to work in every mode, and it cannot go
  # through the proxy: DeepCode builds its own undici dispatcher and ignores
  # HTTP_PROXY, so its calls to the model are direct. Allowing the resolved addresses
  # on the model's own port is what makes the sandbox usable at all; the host
  # resolves them because the container's DNS is limited to its own resolver.
  #
  # Per-address and per-port, so this does not open every port on whatever host
  # serves the model.
  MODEL_ALLOWED=0
  if [ -n "${DEEPSAND_MODEL_ADDRS:-}" ]; then
    OLD_IFS="$IFS"
    IFS=','
    for entry in $DEEPSAND_MODEL_ADDRS; do
      entry="$(echo "$entry" | tr -d ' ')"
      [ -z "$entry" ] && continue
      addr="${entry%:*}"
      port="${entry##*:}"
      if [ -z "$addr" ] || [ -z "$port" ] || [ "$addr" = "$port" ]; then
        log "ignoring malformed model endpoint '$entry'"
        continue
      fi
      if "$IPT" -A OUTPUT -d "$addr" -p tcp --dport "$port" -j ACCEPT; then
        MODEL_ALLOWED=$((MODEL_ALLOWED + 1))
      fi
    done
    IFS="$OLD_IFS"
  fi
  log "model API addresses allowed: $MODEL_ALLOWED"
  if [ "$MODEL_ALLOWED" = "0" ]; then
    log "WARNING: no model endpoint could be allowed, so the sandbox will not be able to reach its model"
  fi

  if [ "$MODE" = "none" ]; then
    # "No network except the model API." Nothing else is added, and no proxy is
    # needed: there is no allowlist for one to enforce.
    reject_all
    log "none policy applied: only DNS and the model API are reachable"
    exit 0
  fi

  # --- the addresses the operator named in the allowlist --------------------
  #
  # These are allowed *directly*, not through the proxy, because that is what they
  # are for: a database, an SSH endpoint or any other protocol that cannot speak
  # HTTP to a proxy. Hostname entries are deliberately absent from this list --
  # they stay proxy-only, which is where the path rules and the DNS-rebinding
  # refusal live.
  #
  # Entry syntax is `ip` (every port) or `ip:port`. IPv4 only, matching the model
  # endpoint handling above; the IPv6 chain below stays deny-by-default, and the
  # host tells the operator when an address entry cannot be enforced here.
  DIRECT_ALLOWED=0
  if [ -n "${DEEPSAND_ALLOW_ADDRS:-}" ]; then
    OLD_IFS="$IFS"
    IFS=','
    for entry in $DEEPSAND_ALLOW_ADDRS; do
      entry="$(echo "$entry" | tr -d ' ')"
      [ -z "$entry" ] && continue
      case "$entry" in
        *:*) addr="${entry%:*}"; port="${entry##*:}" ;;
        *)   addr="$entry"; port="" ;;
      esac
      if [ -z "$addr" ]; then
        log "ignoring malformed allowlist address '$entry'"
        continue
      fi
      if [ -n "$port" ]; then
        if "$IPT" -A OUTPUT -d "$addr" -p tcp --dport "$port" -j ACCEPT; then
          DIRECT_ALLOWED=$((DIRECT_ALLOWED + 1))
        fi
      else
        # Every port, which is what an entry without a port means.
        if "$IPT" -A OUTPUT -d "$addr" -p tcp -j ACCEPT; then
          DIRECT_ALLOWED=$((DIRECT_ALLOWED + 1))
        fi
      fi
    done
    IFS="$OLD_IFS"
  fi
  log "operator-named allowlist addresses allowed directly: $DIRECT_ALLOWED"

  # --- published ports: accept from the host, so a server here is reachable -- #
  #
  # Only appended, never a policy change: these ports are published to the host's
  # loopback by `docker run -p 127.0.0.1:port:port`, so the only peer that can reach
  # them is the operator's own machine. Stating the ACCEPT makes the intent
  # independent of whatever the daemon's default INPUT policy happens to be.
  PUBLISHED=0
  if [ -n "${DEEPSAND_PUBLISHED_PORTS:-}" ]; then
    OLD_IFS="$IFS"
    IFS=','
    for port in $DEEPSAND_PUBLISHED_PORTS; do
      port="$(echo "$port" | tr -d ' ')"
      [ -z "$port" ] && continue
      if "$IPT" -A INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null; then
        PUBLISHED=$((PUBLISHED + 1))
      fi
    done
    IFS="$OLD_IFS"
  fi
  if [ "$PUBLISHED" -gt 0 ]; then
    log "published ports accepted on INPUT: $PUBLISHED"
  fi

  # --- resolve the allowlist proxy ----------------------------------------
  PROXY_IP=""
  if [ -n "$PROXY_ADDR" ]; then
    PROXY_IP="${PROXY_ADDR%%:*}"
    case "$PROXY_ADDR" in *:*) PROXY_PORT="${PROXY_ADDR##*:}" ;; esac
  fi
  if [ -z "$PROXY_IP" ]; then
    PROXY_IP="$(getent hosts "$PROXY_HOST" 2>/dev/null | awk 'NR==1 {print $1}')"
  fi
  if [ -z "$PROXY_IP" ] || [ -z "$PROXY_PORT" ]; then
    log "allowlisted mode requested but the proxy could not be resolved (host='$PROXY_HOST' addr='$PROXY_ADDR')"
    exit 1
  fi
  if [ "$PROXY_IP" = "127.0.0.1" ] || [ "$PROXY_IP" = "0.0.0.0" ]; then
    log "refusing to trust a proxy bound to the container itself ($PROXY_IP)"
    exit 1
  fi
  "$IPT" -A OUTPUT -d "$PROXY_IP" -p tcp --dport "$PROXY_PORT" -j ACCEPT || exit 1
  log "egress proxy allowlisted at $PROXY_IP:$PROXY_PORT"

  # Everything that is not DNS or the proxy is dropped, including the
  # pre-existing ESTABLISHED rule's usefulness to a would-be attacker: a
  # connection can only ever have been established to an allowed target.
  reject_all
  log "allowlisted policy applied: DNS, the model API, $DIRECT_ALLOWED named address(es) and $PROXY_IP:$PROXY_PORT are reachable, nothing else"
else
  # --- internet mode: burn down every non-public destination ---------------
  #
  # 0.0.0.0/8        "this network"
  # 10/8, 172.16/12, 192.168/16    RFC1918 - the Docker bridge gateway (i.e.
  #                                the host) and the user's LAN live here
  # 100.64/10        CGNAT
  # 127/8            loopback (already accepted above via -o lo)
  # 169.254/16       link-local, incl. cloud metadata 169.254.169.254
  # 192.0.0/24       IETF protocol assignments
  # 198.18/15        benchmarking
  # 224/4, 240/4     multicast + reserved
  for net in \
      0.0.0.0/8 \
      10.0.0.0/8 \
      100.64.0.0/10 \
      127.0.0.0/8 \
      169.254.0.0/16 \
      172.16.0.0/12 \
      192.0.0.0/24 \
      192.168.0.0/16 \
      198.18.0.0/15 \
      224.0.0.0/4 \
      240.0.0.0/4 \
      255.255.255.255/32
  do
    "$IPT" -A OUTPUT -d "$net" -j REJECT $REJECT_OPT || exit 1
  done

  "$IPT" -A OUTPUT -j ACCEPT || exit 1
  log "internet policy applied: public egress allowed, host/LAN/link-local blocked"
fi

# --- IPv6: deny by default -------------------------------------------------
# Docker's default bridge has no IPv6 unless explicitly enabled. If it is
# enabled, we refuse to leave a v6 hole that bypasses the v4 policy above.
if command -v ip6tables >/dev/null 2>&1 && ip6tables -L OUTPUT >/dev/null 2>&1; then
  if ip6tables -F OUTPUT >/dev/null 2>&1; then
    ip6tables -A OUTPUT -o lo -j ACCEPT
    ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
    if [ "$MODE" = "internet" ]; then
      ip6tables -A OUTPUT -j ACCEPT
      log "ipv6 policy: allowed (internet mode)"
    else
      ip6tables -A OUTPUT -j REJECT 2>/dev/null || ip6tables -A OUTPUT -j DROP
      log "ipv6 policy: denied (allowlisted mode)"
    fi
  fi
else
  log "ipv6 unavailable in this namespace; nothing to do"
fi

log "final OUTPUT chain:"
"$IPT" -S OUTPUT >&2 || true
exit 0
