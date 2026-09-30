#!/usr/bin/env bash
#
# cat.sh — CatSDK Security Posture Auditor
# A.C Holdings / Team Flames
#
# Read-only DEFENSIVE security research tool. It inspects the LOCAL machine
# for common hardening issues and prints a report. It changes nothing, opens
# no network connections, and touches no other host.
#
# Usage:
#   ./cat.sh            # full audit
#   ./cat.sh --quick    # skip the slow filesystem sweep
#   ./cat.sh --help
#
# Exit code = number of HIGH-severity findings (0 = clean).

set -u

# ---------------------------------------------------------------------------
VERSION="0.1.0"
QUICK=0
HIGH=0; MED=0; LOW=0; OK=0

for arg in "$@"; do
  case "$arg" in
    --quick) QUICK=1 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -n 16
      exit 0 ;;
    *) echo "unknown option: $arg (try --help)"; exit 2 ;;
  esac
done

# ---- pretty output --------------------------------------------------------
if [ -t 1 ]; then
  R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; B=$'\e[36m'; DIM=$'\e[2m'; N=$'\e[0m'
else
  R=""; Y=""; G=""; B=""; DIM=""; N=""
fi

hdr()  { printf '\n%s== %s ==%s\n' "$B" "$1" "$N"; }
high() { HIGH=$((HIGH+1)); printf '  %s[HIGH]%s %s\n' "$R" "$N" "$1"; }
med()  { MED=$((MED+1));   printf '  %s[MED ]%s %s\n' "$Y" "$N" "$1"; }
low()  { LOW=$((LOW+1));   printf '  %s[LOW ]%s %s\n' "$Y" "$N" "$1"; }
ok()   { OK=$((OK+1));     printf '  %s[ OK ]%s %s\n' "$G" "$N" "$1"; }
note() { printf '  %s%s%s\n' "$DIM" "$1" "$N"; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---- banner ---------------------------------------------------------------
cat <<EOF
${B} /\\_/\\   cat.sh — CatSDK Security Posture Auditor v${VERSION}${N}
${B}( o.o )  A.C Holdings / Team Flames${N}
${B} > ^ <   read-only • local-only • changes nothing${N}
${DIM}host: $(hostname 2>/dev/null)   user: $(id -un 2>/dev/null)   $(date)${N}
EOF

# ---------------------------------------------------------------------------
hdr "Account & privilege"
if [ "$(id -u)" -eq 0 ]; then
  low "running as root (fine for a full audit; avoid for daily use)"
else
  ok "not running as root"
fi

# UID 0 accounts other than root
if [ -r /etc/passwd ]; then
  extra_root=$(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)
  if [ -n "$extra_root" ]; then
    high "extra UID-0 account(s): $(echo "$extra_root" | tr '\n' ' ')"
  else
    ok "root is the only UID-0 account"
  fi
  # empty-password accounts
  empty=$(awk -F: '($2==""){print $1}' /etc/passwd 2>/dev/null)
  [ -n "$empty" ] && high "account(s) with empty password field: $empty" || ok "no empty password fields in /etc/passwd"
else
  note "/etc/passwd not readable — skipping account checks"
fi

# ---------------------------------------------------------------------------
hdr "SSH server config"
SSHD=/etc/ssh/sshd_config
if [ -r "$SSHD" ]; then
  get() { grep -Ei "^[[:space:]]*$1[[:space:]]+" "$SSHD" 2>/dev/null | tail -n1 | awk '{print tolower($2)}'; }
  prl=$(get PermitRootLogin)
  case "$prl" in
    yes)  high "PermitRootLogin yes — disable or set prohibit-password" ;;
    ""|prohibit-password|no|without-password) ok "PermitRootLogin = ${prl:-default}" ;;
    *)    low "PermitRootLogin = $prl (review)" ;;
  esac
  pa=$(get PasswordAuthentication)
  [ "$pa" = "yes" ] && med "PasswordAuthentication yes — prefer key-only auth" || ok "PasswordAuthentication = ${pa:-default}"
  x11=$(get X11Forwarding)
  [ "$x11" = "yes" ] && low "X11Forwarding yes — disable if unused" || ok "X11Forwarding = ${x11:-default}"
else
  note "no readable sshd_config (SSH server may not be installed)"
fi

# ---------------------------------------------------------------------------
hdr "Listening network services"
if have ss; then
  LISTEN=$(ss -tulnH 2>/dev/null)
elif have netstat; then
  LISTEN=$(netstat -tuln 2>/dev/null | tail -n +3)
else
  LISTEN=""
  note "neither ss nor netstat available"
fi
if [ -n "$LISTEN" ]; then
  wild=$(echo "$LISTEN" | grep -E '0\.0\.0\.0:|\*:|\[::\]:' | wc -l | tr -d ' ')
  count=$(echo "$LISTEN" | grep -c .)
  note "$count listening socket(s); $wild bound to all interfaces"
  echo "$LISTEN" | awk '{print "      " $0}' | head -n 20
  [ "$wild" -gt 0 ] && low "$wild service(s) reachable on all interfaces — confirm each is intended"
fi

# ---------------------------------------------------------------------------
hdr "Host firewall"
if have ufw && ufw status 2>/dev/null | grep -qi 'status: active'; then
  ok "ufw active"
elif have firewall-cmd && firewall-cmd --state 2>/dev/null | grep -qi running; then
  ok "firewalld running"
elif have nft && [ -n "$(nft list ruleset 2>/dev/null)" ]; then
  ok "nftables ruleset present"
elif have iptables && [ "$(iptables -S 2>/dev/null | grep -c .)" -gt 3 ]; then
  ok "iptables rules present"
else
  med "no active host firewall detected"
fi

# ---------------------------------------------------------------------------
hdr "Sensitive file permissions"
chk() { # path  max-octal-perms  label
  [ -e "$1" ] || return
  p=$(stat -c '%a' "$1" 2>/dev/null) || return
  if [ "$p" -gt "$2" ] 2>/dev/null; then
    med "$1 is mode $p (expected <= $2) — $3"
  else
    ok "$1 mode $p"
  fi
}
chk /etc/shadow 640 "should not be world/group readable"
chk /etc/passwd 644 "should not be world-writable"
chk /etc/sudoers 440 "tighten permissions"
[ -d "$HOME/.ssh" ] && chk "$HOME/.ssh" 700 "private key dir"
for k in "$HOME"/.ssh/id_*; do
  [ -f "$k" ] && [ "${k##*.}" != "pub" ] && chk "$k" 600 "private key"
done

# ---------------------------------------------------------------------------
if [ "$QUICK" -eq 0 ]; then
  hdr "Filesystem sweep (world-writable & SUID)"
  note "scanning /etc /usr /opt /home … (use --quick to skip)"
  ww=$(find /etc /usr/local /opt /home -xdev -type f -perm -0002 2>/dev/null | head -n 20)
  if [ -n "$ww" ]; then
    med "world-writable file(s) found:"; echo "$ww" | awk '{print "      " $0}'
  else
    ok "no world-writable files in scanned paths"
  fi
  suid=$(find /usr /bin /sbin -xdev -perm -4000 -type f 2>/dev/null | wc -l | tr -d ' ')
  note "SUID binaries in /usr /bin /sbin: $suid (review with: find / -perm -4000 -type f)"
else
  hdr "Filesystem sweep"
  note "skipped (--quick)"
fi

# ---------------------------------------------------------------------------
hdr "Pending updates"
if have apt-get; then
  n=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst')
  [ "$n" -gt 0 ] && med "$n package update(s) available (apt)" || ok "apt reports no pending upgrades"
elif have dnf; then
  dnf -q check-update >/dev/null 2>&1 && ok "dnf: system up to date" || med "dnf: updates available"
else
  note "no apt/dnf — check your package manager manually"
fi

# ---------------------------------------------------------------------------
printf '\n%s== Summary ==%s\n' "$B" "$N"
printf '  %sHIGH %d%s   %sMED %d%s   %sLOW %d%s   %sOK %d%s\n' \
  "$R" "$HIGH" "$N" "$Y" "$MED" "$N" "$Y" "$LOW" "$N" "$G" "$OK" "$N"
[ "$HIGH" -eq 0 ] && printf '  %sNo high-severity findings.%s\n' "$G" "$N" \
                   || printf '  %sAddress HIGH findings first.%s\n' "$R" "$N"
note "This is a heuristic local audit, not a guarantee. Verify findings before acting."

exit "$HIGH"
