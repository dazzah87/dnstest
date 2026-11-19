#!/usr/bin/env bash

set -u
export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/homebrew/bin"

VERSION="2.1.0"
SCRIPT_NAME=${0##*/}
EXIT_OK=0; EXIT_FAIL=1; EXIT_USAGE=2; EXIT_DEPS=3

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m';    C_BOLD=$'\033[1m'
  C_GREEN=$'\033[0;32m'; C_BGREEN=$'\033[1;32m'; C_YELLOW=$'\033[0;33m'
  C_ORANGE=$'\033[0;38;5;208m'
  C_RED=$'\033[0;31m';   C_BRED=$'\033[1;31m';   C_CYAN=$'\033[0;36m'
else
  C_RESET=""; C_BOLD=""; C_GREEN=""; C_BGREEN=""; C_YELLOW=""
  C_ORANGE=""; C_RED=""; C_BRED=""; C_CYAN=""
fi

TMP_DIR=""
cleanup() {
  local pids
  pids=$(jobs -p 2>/dev/null)
  [ -n "$pids" ] && kill $pids 2>/dev/null
  [ -n "$TMP_DIR" ] && rm -rf "$TMP_DIR"
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT TERM

mode="ipv4"; format="table"; sort_mode="fastest"
DO_AUDIT=1; DO_IP=1
TIMEOUT_SEC=2
REPEAT_COUNT=1

HAGEZI_SERVERS="
root  188.34.161.210  2a01:4f8:c17:1c66::1  Root
wurzn 159.69.155.94   2a01:4f8:1c1c:d363::1 Wurzn
ctif  162.55.58.40    2a01:4f8:1c19:6c19::1 CTIF
"

PROVIDERS="
Cloudflare   1.1.1.1         2606:4700:4700::1111
Google       8.8.8.8         2001:4860:4860::8888
Quad9        9.9.9.9         2620:fe::fe
OpenDNS      208.67.222.222  2620:119:35::35
DNS4EU       86.54.11.1      2a13:1001::86:54:11:1
AdGuard-DNS  94.140.14.140   2a10:50c0::1:ff
ControlD     76.76.2.0       2606:1a40::
DNSForge     176.9.93.198    2a01:4f8:151:34aa::198
"

DOMAINS2TEST="
amazon.de
apple.com
cloudflare.com
denic.de
facebook.com
google.com
microsoft.com
paypal.com
tiktok.com
wikipedia.org
"

DNSSEC_TESTS=("Valid|" "Invalid|badsig-" "Expired|expiredsig-" "Missing|nosig-")
DNSSEC_ALGOS=("13:ECDSA P-256" "14:ECDSA P-384" "15:Ed25519")

usage() {
  cat <<EOF
$SCRIPT_NAME $VERSION - DNS resolver benchmark

Usage:
  $SCRIPT_NAME [ipv4|ipv6|all] [table|csv|tsv|json] [options]
  $SCRIPT_NAME check [-4|-6] [-v] [root|wurzn|ctif ...]
  $SCRIPT_NAME -h|--help | -V|--version

Benchmark options:
  --sort fastest|slowest   sort by average latency (default: fastest)
  --repeat N               run the full domain x provider matrix N times (default: 1)
  --timeout SEC            per-query timeout in whole seconds (default: 2)
  --quick                  latency only: skip DNSSEC audit, ECS check and IP lookup
  --no-audit               skip DNSSEC audit and ECS check
  --no-ip                  skip the public IP lookup (contacts addr.tools and ipinfo.io)

Benchmark examples:
  $SCRIPT_NAME
  $SCRIPT_NAME all csv --sort slowest
  $SCRIPT_NAME ipv4 table --repeat 3 --timeout 1

Benchmark output:
  One column per test domain, Average (mean of the successful queries), Rating
  and Privacy (ECS). Below the table: DNSSEC audit results and reference values.

Check mode:
  Tests every DNS server over Do53, DoT, DoH and DoQ (IPv4 and IPv6):
  resolution, DNSSEC validation, blocking behaviour and ping latency.
    -4 / -6        test IPv4 / IPv6 only
    -v, --verbose  show the result of every single query
  Requires kdig (Knot DNS utilities). DoH and DoQ need a recent kdig built with
  HTTP/2 and QUIC support; otherwise those tests are skipped.

Requires: bash, dig or drill (benchmark), kdig (check); curl is optional.
Set NO_COLOR=1 to disable colored output.
Exit codes: 0 ok, 1 test failed, 2 invalid arguments, 3 missing dependency
EOF
}

version() {
  cat <<EOF
$SCRIPT_NAME $VERSION
License GPLv3: GNU GPL version 3 <https://www.gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
EOF
}

die_usage() {
  echo "error: $1" >&2
  echo "Try '$SCRIPT_NAME --help'." >&2
  exit $EXIT_USAGE
}

posint() {
  case ${2:-} in ''|*[!0-9]*) die_usage "$1 requires a positive integer" ;; esac
  POSINT=$((10#$2))
  [ "$POSINT" -ge 1 ] || die_usage "$1 must be at least 1"
}

has_ipv6() {
  local target=${1:-2606:4700:4700::1111}
  if command -v ip >/dev/null 2>&1; then
    ip -6 route get "$target" >/dev/null 2>&1; return $?
  elif command -v route >/dev/null 2>&1; then
    route -n get -inet6 "$target" >/dev/null 2>&1; return $?
  fi
  [ -n "${dig_cmd:-}" ] || return 0
  "$dig_cmd" +short +tries=1 +time=2 @"$target" www.google.com 2>/dev/null | grep -q '^[0-9]'
}

run_query() {
  local ip=$1 domain=$2 type=${3:-A} secs=$TIMEOUT_SEC
  local cmd=(drill @"$ip" "$domain" "$type") pre=()
  if [ "$dig_cmd" = "dig" ]; then
    cmd=(dig +tries=1 +time="$TIMEOUT_SEC" +stats @"$ip" "$domain" "$type")
    secs=$((TIMEOUT_SEC + 1))
  fi
  [ -n "$TIMEOUT_CMD" ] && pre=("$TIMEOUT_CMD" "${secs}s")
  "${pre[@]+"${pre[@]}"}" "${cmd[@]}" 2>&1 </dev/null
}

is_timeout() {
  [ "$1" -eq 124 ] && return 0
  [ "$dig_cmd" = "dig" ] && [ "$1" -eq 9 ] && return 0
  case "$2" in *"timed out"*) return 0 ;; esac
  return 1
}

rcode_of() {
  printf '%s\n' "$1" | awk 'match($0, /(status|rcode): [A-Z]+/) {
    s = substr($0, RSTART, RLENGTH); sub(/.*: /, "", s); print s; exit }'
}

has_answer() {
  printf '%s\n' "$1" | awk '/ANSWER SECTION/ {f=1; next} f && NF==0 {exit} f {found=1} END {exit !found}'
}

public_ip() {
  local fam=$1 chars ip="" org="Not available"
  if [ "$fam" = 4 ]; then chars='0-9.'; else chars='a-fA-F0-9:'; fi
  ip=$(curl -s -m 2 "https://myipv${fam}.addr.tools/plain" 2>/dev/null | tr -dc "$chars")
  if { [ "$fam" = 4 ] && [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; } ||
     { [ "$fam" = 6 ] && [[ "$ip" == *:* ]]; }; then
    org=$(curl -s -m 2 "https://ipinfo.io/${ip}/org" 2>/dev/null | sed -E 's/^AS[0-9]+ *//' | tr -dc '[:print:]')
    [ -z "$org" ] && org="Not available"
  else
    ip="Not available"
  fi
  echo "$ip ($org)"
}

ecs_check() {
  local idx=$1 out ecs="Strict"
  out=$(run_query "${provider_ips[$idx]}" o-o.myaddr.l.google.com TXT)
  if [ -z "$(rcode_of "$out")" ]; then
    ecs="n/a"
  elif grep -qi 'edns0-client-subnet' <<<"$out"; then
    ecs="Sent"
  fi
  echo "$ecs" > "$TMP_DIR/ecs.$idx"
}

dnssec_audit() {
  local idx=$1 ip fails="" t tname prefix alg a aname dom out st ans msg
  ip=${provider_ips[$idx]}
  for t in "${DNSSEC_TESTS[@]}"; do
    tname=${t%%|*}; prefix=${t#*|}
    for alg in "${DNSSEC_ALGOS[@]}"; do
      a=${alg%%:*}; aname=${alg#*:}
      dom="${prefix}${RUNID}.test-alg${a}.dnscheck.tools"
      out=$(run_query "$ip" "$dom" TXT)
      st=$(rcode_of "$out")
      ans=0; has_answer "$out" && ans=1
      msg=""
      if [ -z "$st" ]; then
        msg="? no response"
      elif [ -z "$prefix" ]; then
        { [ "$st" = NOERROR ] && [ "$ans" = 1 ]; } || msg="- valid zone did not resolve ($st)"
      else
        case $st in
          SERVFAIL) ;;
          NOERROR)  if [ "$ans" = 1 ]; then msg="- answer returned, signature not rejected"
                    else msg="? NOERROR without answer"; fi ;;
          *)        msg="? unexpected status $st" ;;
        esac
      fi
      [ -n "$msg" ] && fails+="  ${msg%% *} $tname signature ($aname): ${msg#* }"$'\n'
    done
  done
  printf '%s' "$fails" > "$TMP_DIR/dnssec.$idx"
}

audit_worker() { ecs_check "$1"; dnssec_audit "$1"; }

fmt() {
  case $1 in
    ''|*[!0-9]*) FMT=$1 ;;
    *) printf -v FMT '%d.%02d%s' $(($1 / 100)) $(($1 % 100)) "${2:-}" ;;
  esac
}

rate() {
  RATING="-"; VC=""
  case $1 in
    ''|*[!0-9]*) case $1 in error|timeout) VC=$C_RED ;; esac; return 0 ;;
  esac
  if   (( $1 < 2000 ));   then RATING="Excellent"; VC=$C_BGREEN
  elif (( $1 <= 5000 ));  then RATING="Very good"; VC=$C_GREEN
  elif (( $1 <= 10000 )); then RATING="OK";        VC=$C_YELLOW
  elif (( $1 <= 12000 )); then RATING="Average";   VC=$C_ORANGE
  elif (( $1 <= 20000 )); then RATING="Slow";      VC=$C_RED
  else                         RATING="Very slow"; VC=$C_BRED
  fi
}

cell() {
  local pad=$(($3 - ${#1}))
  printf '%s%s%s' "$2" "$1" "${2:+$C_RESET}"
  [ "$pad" -lt 0 ] && pad=0
  printf '%*s' "$pad" ""
}

detect_tools() {
  local c
  if command -v dig >/dev/null 2>&1; then
    dig_cmd="dig"
  elif command -v drill >/dev/null 2>&1; then
    dig_cmd="drill"
  else
    echo "error: neither 'dig' nor 'drill' was found. Please install dnsutils/bind-tools (dig) or ldns (drill)." >&2
    exit $EXIT_DEPS
  fi
  TIMEOUT_CMD=""
  for c in timeout gtimeout; do
    command -v "$c" >/dev/null 2>&1 && { TIMEOUT_CMD=$c; break; }
  done
  if [ "$DO_IP" = 1 ] && ! command -v curl >/dev/null 2>&1; then
    echo "note: curl not found, skipping the public IP lookup." >&2
    DO_IP=0
  fi
}

load_lists() {
  local d name v4 v6 lbl list=$PROVIDERS

  if ! has_ipv6; then
    if [ "$mode" = ipv6 ]; then
      echo "error: IPv6 support not found. Unable to do the ipv6 test." >&2
      exit $EXIT_FAIL
    elif [ "$mode" = all ]; then
      echo "note: IPv6 not available on this connection, testing IPv4 only." >&2
      mode=ipv4
    fi
  fi

  domains_arr=(); domain_labels=()
  for d in $DOMAINS2TEST; do
    domains_arr+=("$d")
    domain_labels+=("${d%.*}")
  done

  while read -r name v4 v6 lbl; do
    [ -n "$name" ] && list+=$'\n'"HaGeZi-$lbl $v4 $v6"
  done <<< "$HAGEZI_SERVERS"

  provider_names=(); provider_ips=()
  while read -r name v4 v6; do
    [ -z "$name" ] && continue
    if [ "$mode" != ipv6 ]; then provider_names+=("$name");    provider_ips+=("$v4"); fi
    if [ "$mode" != ipv4 ]; then provider_names+=("$name-v6"); provider_ips+=("$v6"); fi
  done <<< "$list"

  totaldomains=${#domains_arr[@]}
  totalproviders=${#provider_ips[@]}
}

measure() {
  local pass di pi k d output rc ttime rcode n=0
  local total=$((REPEAT_COUNT * totaldomains * totalproviders))
  sum_time=(); count_success=(); count_timeout=()

  for (( pass=1; pass<=REPEAT_COUNT; pass++ )); do
    for (( di=0; di<totaldomains; di++ )); do
      d=${domains_arr[$di]}
      for (( pi=0; pi<totalproviders; pi++ )); do
        k=$(( di * totalproviders + pi ))
        n=$((n + 1))
        if [ "$show_progress" = 1 ]; then
          printf '\rTesting DNS servers... [%d/%d] pass %d/%d  %-20s -> %-24s' \
            "$n" "$total" "$pass" "$REPEAT_COUNT" "$d" "${provider_names[$pi]}" >&2
        fi

        output=$(run_query "${provider_ips[$pi]}" "$d" A)
        rc=$?
        ttime=$(printf '%s\n' "$output" | awk '/Query time:/ {print $4; exit}')
        case "$ttime" in ''|*[!0-9]*) ttime="" ;; esac
        rcode=$(rcode_of "$output")

        if is_timeout "$rc" "$output"; then
          count_timeout[$k]=$(( ${count_timeout[$k]:-0} + 1 ))
        elif [ -n "$ttime" ] && [ "$rcode" = "NOERROR" ]; then
          sum_time[$k]=$(( ${sum_time[$k]:-0} + ttime ))
          count_success[$k]=$(( ${count_success[$k]:-0} + 1 ))
        fi
      done
    done
  done
}

run_audits() {
  local pi
  [ "$show_progress" = 1 ] && printf '\r%-100s' "Running DNSSEC / privacy checks..." >&2
  if [ "$DO_IP" = 1 ]; then
    public_ip 4 > "$TMP_DIR/ip4" &
    public_ip 6 > "$TMP_DIR/ip6" &
  fi
  if [ "$DO_AUDIT" = 1 ]; then
    for (( pi=0; pi<totalproviders; pi++ )); do audit_worker "$pi" & done
  fi
  wait
}

aggregate() {
  local pi di k n sum dsucc v timedout
  cell_val=(); avg=(); ecs_val=(); best_idx=-1

  for (( pi=0; pi<totalproviders; pi++ )); do
    n=0; sum=0; timedout=0
    for (( di=0; di<totaldomains; di++ )); do
      k=$(( di * totalproviders + pi ))
      dsucc=${count_success[$k]:-0}
      if [ "$dsucc" -gt 0 ]; then
        v=$(( (${sum_time[$k]} * 100 + dsucc / 2) / dsucc ))
        n=$((n + 1)); sum=$((sum + v))
      elif [ "${count_timeout[$k]:-0}" -gt 0 ]; then
        v=timeout; timedout=1
      else
        v=error
      fi
      cell_val[$k]=$v
    done

    if [ "$n" -gt 0 ]; then
      avg[$pi]=$(( (sum + n / 2) / n ))
      if [ "$best_idx" -lt 0 ] || [ "${avg[$pi]}" -lt "${avg[$best_idx]}" ]; then best_idx=$pi; fi
    elif [ "$timedout" = 1 ]; then
      avg[$pi]=timeout
    else
      avg[$pi]=error
    fi

    ecs_val[$pi]="n/a"
    [ -f "$TMP_DIR/ecs.$pi" ] && ecs_val[$pi]=$(<"$TMP_DIR/ecs.$pi")
  done
}

sorted_order() {
  local pi key flags="-k1,1n"
  [ "$sort_mode" = slowest ] && flags="-k1,1nr"
  for (( pi=0; pi<totalproviders; pi++ )); do
    case ${avg[$pi]} in ''|*[!0-9]*) key=99999999 ;; *) key=${avg[$pi]} ;; esac
    echo "$key $pi"
  done | sort $flags -k2,2n | cut -d' ' -f2
}

print_table() {
  local pi di k pw=8 ipw=2 avgw=7 color
  local -a colw

  if [ -f "$TMP_DIR/ip4" ]; then
    printf '\n%sYour public IP:%s\n- IPv4: %s\n- IPv6: %s\n' \
      "$C_BOLD" "$C_RESET" "$(<"$TMP_DIR/ip4")" "$(<"$TMP_DIR/ip6")"
  fi
  echo

  for (( di=0; di<totaldomains; di++ )); do colw[$di]=${#domain_labels[$di]}; done
  for (( pi=0; pi<totalproviders; pi++ )); do
    [ ${#provider_names[$pi]} -gt $pw ]  && pw=${#provider_names[$pi]}
    [ ${#provider_ips[$pi]} -gt $ipw ]   && ipw=${#provider_ips[$pi]}
    fmt "${avg[$pi]}" ms; [ ${#FMT} -gt $avgw ] && avgw=${#FMT}
    for (( di=0; di<totaldomains; di++ )); do
      fmt "${cell_val[$((di * totalproviders + pi))]}" ms
      [ ${#FMT} -gt "${colw[$di]}" ] && colw[$di]=${#FMT}
    done
  done
  pw=$((pw + 2)); ipw=$((ipw + 2)); avgw=$((avgw + 2))

  cell Provider "$C_BOLD" $pw
  cell IP "$C_BOLD" $ipw
  for (( di=0; di<totaldomains; di++ )); do
    cell "${domain_labels[$di]}" "$C_BOLD" $((colw[di] + 2))
  done
  cell Average "$C_BOLD" $avgw
  cell Rating "$C_BOLD" 11
  cell Privacy "$C_BOLD" 9
  echo

  for pi in $(sorted_order); do
    color=""; [ "$pi" = "$best_idx" ] && color=$C_CYAN
    cell "${provider_names[$pi]}" "$color" $pw
    cell "${provider_ips[$pi]}" "" $ipw
    for (( di=0; di<totaldomains; di++ )); do
      k=$(( di * totalproviders + pi ))
      fmt "${cell_val[$k]}" ms; rate "${cell_val[$k]}"
      cell "$FMT" "$VC" $((colw[di] + 2))
    done
    fmt "${avg[$pi]}" ms; rate "${avg[$pi]}"
    cell "$FMT" "$VC" $avgw
    cell "$RATING" "$VC" 11
    case ${ecs_val[$pi]} in Strict) color=$C_GREEN ;; Sent) color=$C_YELLOW ;; *) color="" ;; esac
    cell "${ecs_val[$pi]}" "$color" 9
    echo
  done
}

print_audit() {
  local pi found=0
  [ "$DO_AUDIT" = 1 ] || return 0
  for (( pi=0; pi<totalproviders; pi++ )); do
    [ -s "$TMP_DIR/dnssec.$pi" ] || continue
    if [ $found = 0 ]; then
      printf '\n%s--- DNSSEC Audit Failures ---%s\n' "$C_BOLD" "$C_RESET"
      echo "(- = failed, ? = inconclusive)"
      found=1
    fi
    printf '%s%s%s (%s):\n' "$C_YELLOW" "${provider_names[$pi]}" "$C_RESET" "${provider_ips[$pi]}"
    cat "$TMP_DIR/dnssec.$pi"
  done
  [ $found = 1 ] || printf '\nGreat! All DNS responses were successfully authenticated using DNSSEC.\n'
}

print_legend() {
  printf '\n%s--- Info ---%s\n' "$C_BOLD" "$C_RESET"
  echo "'Strict' = No ECS (EDNS Client Subnet) information is sent."
  echo "'Sent' = Part of your client subnet is shared via ECS."
  echo
  printf '%s--- DNS Resolution Reference Values ---%s\n' "$C_BOLD" "$C_RESET"
  printf '%-10s %-12s %s\n' "< 20ms"    "Excellent" "Very fast response, often due to a nearby resolver and/or a warm cache."
  printf '%-10s %-12s %s\n' "20-50ms"   "Very good" "Common target range for good user experience."
  printf '%-10s %-12s %s\n' "50-100ms"  "OK"        "Usually fine, but can add noticeable delay if a page triggers many lookups."
  printf '%-10s %-12s %s\n' "100-120ms" "Average"   "Often cited as the upper end of average DNS lookup time."
  printf '%-10s %-12s %s\n' "120-200ms" "Slow"      "Suggests distance, routing/latency, resolver load, or extra steps."
  printf '%-10s %-12s %s\n\n' "> 200ms"  "Very slow" "Frequently indicates a real performance or reachability issue."
}

print_delimited() {
  local sep=$1 d pi di
  printf 'provider%sip' "$sep"
  for d in "${domains_arr[@]}"; do printf '%s%s' "$sep" "$d"; done
  printf '%saverage%srating%sprivacy\n' "$sep" "$sep" "$sep"

  for pi in $(sorted_order); do
    printf '%s%s%s' "${provider_names[$pi]}" "$sep" "${provider_ips[$pi]}"
    for (( di=0; di<totaldomains; di++ )); do
      fmt "${cell_val[$((di * totalproviders + pi))]}"; printf '%s%s' "$sep" "$FMT"
    done
    fmt "${avg[$pi]}"; rate "${avg[$pi]}"
    printf '%s%s%s%s%s%s\n' "$sep" "$FMT" "$sep" "$RATING" "$sep" "${ecs_val[$pi]}"
  done
}

json_val() {
  fmt "$1"
  case $FMT in ''|*[!0-9.]*) printf '"%s"' "$FMT" ;; *) printf '%s' "$FMT" ;; esac
}

print_json() {
  local pi di first=1
  printf '[\n'
  for pi in $(sorted_order); do
    [ $first = 1 ] || printf ',\n'
    first=0
    printf '  {"provider":"%s","ip":"%s","results":{' "${provider_names[$pi]}" "${provider_ips[$pi]}"
    for (( di=0; di<totaldomains; di++ )); do
      [ "$di" -eq 0 ] || printf ','
      printf '"%s":' "${domains_arr[$di]}"
      json_val "${cell_val[$((di * totalproviders + pi))]}"
    done
    printf '},"average":'
    json_val "${avg[$pi]}"
    rate "${avg[$pi]}"
    printf ',"rating":"%s","privacy":"%s"}' "$RATING" "${ecs_val[$pi]}"
  done
  printf '\n]\n'
}

parse_perf_args() {
  local arg
  for arg in "$@"; do
    case "$arg" in
      -h|--help)    usage; exit $EXIT_OK ;;
      -V|--version) version; exit $EXIT_OK ;;
    esac
  done

  while [ $# -gt 0 ]; do
    case "$1" in
      ipv4|ipv6|all)      mode=$1 ;;
      table|csv|tsv|json) format=$1 ;;
      --sort)
        [ $# -gt 1 ] || die_usage "--sort requires a value"
        shift
        case "$1" in
          fastest|slowest) sort_mode=$1 ;;
          *) die_usage "unsupported sort mode: $1" ;;
        esac
        ;;
      --repeat)
        [ $# -gt 1 ] || die_usage "--repeat requires a value"
        shift; posint --repeat "$1"; REPEAT_COUNT=$POSINT
        ;;
      --timeout)
        [ $# -gt 1 ] || die_usage "--timeout requires a value"
        shift; posint --timeout "$1"; TIMEOUT_SEC=$POSINT
        ;;
      --quick)    DO_AUDIT=0; DO_IP=0 ;;
      --no-audit) DO_AUDIT=0 ;;
      --no-ip)    DO_IP=0 ;;
      *) die_usage "unknown argument: $1" ;;
    esac
    shift
  done
}

run_perf() {
  parse_perf_args "$@"
  detect_tools
  load_lists

  TMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t dnsperf)
  RUNID=$(printf '%04x%04x' "$RANDOM" "$RANDOM")
  show_progress=0
  [ -t 2 ] && show_progress=1

  measure
  if [ "$DO_AUDIT" = 1 ] || [ "$DO_IP" = 1 ]; then run_audits; fi
  [ "$show_progress" = 1 ] && printf '\r%*s\r' 110 "" >&2
  aggregate

  case "$format" in
    table) print_table; print_audit; print_legend ;;
    csv)   print_delimited "," ;;
    tsv)   print_delimited $'\t' ;;
    json)  print_json ;;
  esac

  if [ "$best_idx" -lt 0 ]; then
    echo "error: all tested providers failed (error or timeout)." >&2
    exit $EXIT_FAIL
  fi
  exit $EXIT_OK
}

CK_PROTOCOLS="Do53 DoT DoH DoQ"
CK_RESOLVE_DOMAINS=(example.com wikipedia.org)
CK_DNSSEC_OK="isc.org"
CK_DNSSEC_BOGUS=(dnssec-failed.org sigfail.verteiltesysteme.net)
CK_BLOCK_DOMAIN="app-measurement.com"
CK_TIMEOUT=5
CK_PING_COUNT=10

install_hint() {
  local id="" like="" cmd=""
  echo "${C_RED}kdig (Knot DNS utilities) is required but not installed.${C_RESET}"
  echo
  if [ "$(uname -s)" = Darwin ]; then
    id=macos
  elif [ -r /etc/os-release ]; then
    id=$(. /etc/os-release && echo "${ID:-}")
    like=$(. /etc/os-release && echo "${ID_LIKE:-}")
  fi
  case " $id $like " in
    *" macos "*)                             cmd="brew install knot   (Homebrew: https://brew.sh)" ;;
    *debian*|*ubuntu*|*raspbian*)            cmd="sudo apt install knot-dnsutils" ;;
    *fedora*|*rhel*|*centos*|*rocky*|*alma*) cmd="sudo dnf install knot-utils   (RHEL/Rocky/Alma: enable EPEL first)" ;;
    *arch*|*manjaro*)                        cmd="sudo pacman -S knot" ;;
    *suse*)                                  cmd="sudo zypper install knot" ;;
    *alpine*)                                cmd="sudo apk add knot-utils" ;;
  esac
  if [ -n "$cmd" ]; then
    echo "Install it with:"
    echo "  ${C_BOLD}$cmd${C_RESET}"
  else
    echo "Install the Knot DNS utilities with your package manager, e.g.:"
    echo "  Debian/Ubuntu:  sudo apt install knot-dnsutils"
    echo "  Fedora/RHEL:    sudo dnf install knot-utils"
    echo "  Arch:           sudo pacman -S knot"
    echo "  openSUSE:       sudo zypper install knot"
    echo "  Alpine:         sudo apk add knot-utils"
    echo "  macOS:          brew install knot"
  fi
  echo
  echo "Note: DoH and DoQ need a recent kdig built with HTTP/2 and QUIC support."
  echo "If those tests show SKIP, install a newer kdig:"
  echo "  Debian/Ubuntu:  CZ.NIC repository, https://pkg.labs.nic.cz/doc/?project=knot-dns"
  echo "  Other systems:  https://www.knot-dns.cz/download/"
}

kq() {
  local proto=$1 ip=$2 host=$3 dom=$4; shift 4
  local a=() out rc
  case $proto in
    DoT) a=(+tls) ;;
    DoH) a=(+https=/dns-query) ;;
    DoQ) a=(+quic) ;;
  esac
  [ "$proto" != Do53 ] && a+=(+tls-ca +tls-hostname="$host" +tls-sni="$host")
  out=$( (kdig @"$ip" ${a[@]+"${a[@]}"} +time="$CK_TIMEOUT" +retry=0 "$@" "$dom" A) 2>&1 </dev/null ); rc=$?
  printf '%s\n' "$out"
  [ $rc -ge 128 ] && echo "kdig crashed (signal $((rc-128)))"
  return 0
}

kstatus()      { grep -m1 -oE 'status: [A-Z]+' <<<"$1" || echo 'no response'; }
kfirst_a()     { awk '/ANSWER SECTION/{f=1;next} f&&NF==0{exit} f&&$4=="A"{print $5;exit}' <<<"$1"; }
kede()         { grep -m1 -oE 'EDE: [0-9]+ \([^)]*\)' <<<"$1"; }
kunsupported() { grep -qiE 'invalid parameter|not (compiled|supported|available)|unsupported|kdig crashed' <<<"$1"; }

kmark() {
  case $1 in
    1) printf '%s✓%s' "$C_GREEN" "$C_RESET" ;;
    2) printf '%s?%s' "$C_YELLOW" "$C_RESET" ;;
    *) printf '%s✗%s' "$C_RED" "$C_RESET" ;;
  esac
}

ktrace() {
  [ "$CK_VERBOSE" = 1 ] || return 0
  local s a e
  s=$(kstatus "$2"); a=$(kfirst_a "$2"); e=$(kede "$2")
  [ -z "$a" ] && a=$(awk 'NF' <<<"$2" | grep -E '^[0-9.]+$' | head -1)
  grep -q 'status:' <<<"$2" || s=""
  printf '        %-42s %s%s%s\n' "$1" "${s#status: }" "${a:+ $a}" "${e:+ [$e]}"
}

ping_avg() {
  local ip=$1 fam=$2 out avg c=()
  command -v ping >/dev/null 2>&1 || return 0
  if [ "$fam" = 6 ]; then
    if command -v ping6 >/dev/null 2>&1; then c=(ping6); else c=(ping -6); fi
  else
    c=(ping)
  fi
  out=$("${c[@]}" -c "$CK_PING_COUNT" -i 0.2 "$ip" 2>&1 </dev/null)

  grep -q 'transmitted' <<<"$out" || out=$("${c[@]}" -c "$CK_PING_COUNT" "$ip" 2>&1 </dev/null)
  avg=$(sed -nE 's#.*min/avg/max[^=]*= *[0-9.]+/([0-9.]+)/.*#\1#p' <<<"$out" | head -1)
  [ -n "$avg" ] && awk -v x="$avg" 'BEGIN{printf "%d", int(x+0.5)}'
  return 0
}

check_proto() {
  local proto=$1 ip=$2 fqdn=$3 name=$4
  local out first sess d i reason details="" rok=1 dok=1 bok=1 verdict
  local bogus_servfail=0 bogus_open=0

  first=$(kq "$proto" "$ip" "$fqdn" "${CK_RESOLVE_DOMAINS[0]}")
  if kunsupported "$first"; then
    printf '  %-5s %sSKIP%s  not supported by this kdig build\n' "$proto" "$C_YELLOW" "$C_RESET"
    grep -q 'kdig crashed' <<<"$first" && printf '        kdig crashed, update kdig (see --help)\n'
    CK_SKIP=$((CK_SKIP + 1)); return
  fi
  if ! grep -q 'status:' <<<"$first"; then
    printf '  %-5s %sFAIL%s  no response (connection failed, timeout or certificate error)\n' "$proto" "$C_RED" "$C_RESET"
    reason=$(grep -m1 -iE 'warning|error|fail' <<<"$first")
    [ -z "$reason" ] && reason=$(awk 'NF' <<<"$first" | tail -1)
    [ -n "$reason" ] && printf '        kdig: %s\n' "$reason"
    [ "$proto" = DoQ ] && printf '        (DoQ uses UDP port 853, which some networks block)\n'
    CK_FAIL=$((CK_FAIL + 1)); return
  fi
  sess=$(grep -m1 -oE ';; (TLS|HTTP|QUIC) session \([^)]*\)' <<<"$first" | sed -E 's/.*\(([^)]*)\)/\1/')

  for i in "${!CK_RESOLVE_DOMAINS[@]}"; do
    d=${CK_RESOLVE_DOMAINS[$i]}
    if [ "$i" = 0 ]; then out=$first; else out=$(kq "$proto" "$ip" "$fqdn" "$d"); fi
    ktrace "resolve $d" "$out"
    if ! grep -q 'status: NOERROR' <<<"$out" || [ -z "$(kfirst_a "$out")" ]; then
      rok=0; details+="        resolve $d: $(kstatus "$out")"$'\n'
    fi
  done

  out=$(kq "$proto" "$ip" "$fqdn" "$CK_DNSSEC_OK")
  ktrace "dnssec valid $CK_DNSSEC_OK" "$out"
  if ! grep -q 'status: NOERROR' <<<"$out"; then
    dok=0; details+="        dnssec $CK_DNSSEC_OK (valid): $(kstatus "$out"), expected NOERROR"$'\n'
  fi
  for d in "${CK_DNSSEC_BOGUS[@]}"; do
    out=$(kq "$proto" "$ip" "$fqdn" "$d")
    ktrace "dnssec bogus $d" "$out"
    case $(kstatus "$out") in
      "status: SERVFAIL") bogus_servfail=$((bogus_servfail + 1)) ;;
      "status: NOERROR")  bogus_open=$((bogus_open + 1))
                          details+="        dnssec $d (bogus): NOERROR, signature not validated"$'\n' ;;
      *)                  details+="        dnssec $d (bogus): $(kstatus "$out" | sed 's/status: //'), test domain may no longer exist"$'\n' ;;
    esac
  done
  if [ $bogus_open -gt 0 ]; then dok=0
  elif [ $dok = 1 ] && [ $bogus_servfail -eq 0 ]; then dok=2
  fi

  out=$(kq "$proto" "$ip" "$fqdn" "$CK_BLOCK_DOMAIN" +short)
  ktrace "block $CK_BLOCK_DOMAIN" "$out"
  if [ "$name" = ctif ]; then
    [[ "$out" == *0.0.0.0* ]] && { bok=0; details+="        block $CK_BLOCK_DOMAIN: blocked, but ctif is threat-only"$'\n'; }
  else
    [[ "$out" != *0.0.0.0* ]] && { bok=0; details+="        block $CK_BLOCK_DOMAIN: not blocked"$'\n'; }
  fi

  if [ $rok = 0 ] || [ $dok = 0 ] || [ $bok = 0 ]; then
    verdict="${C_RED}FAIL${C_RESET}"; CK_FAIL=$((CK_FAIL + 1))
  elif [ $dok = 2 ]; then
    verdict="${C_YELLOW}WARN${C_RESET}"; CK_WARN=$((CK_WARN + 1))
  else
    verdict="${C_GREEN}OK  ${C_RESET}"; CK_PASS=$((CK_PASS + 1))
  fi

  printf '  %-5s %s  resolve %s  dnssec %s  block %s%s\n' \
    "$proto" "$verdict" "$(kmark $rok)" "$(kmark $dok)" "$(kmark $bok)" "${sess:+   [$sess]}"
  [ -n "$details" ] && printf '%s' "$details"
  return 0
}

run_check() {
  local families="4 6" family_forced=0 select="" arg p
  local name v4 v6 lbl fqdn fam ip avg pingtxt rank=""
  CK_VERBOSE=0; CK_PASS=0; CK_FAIL=0; CK_SKIP=0; CK_WARN=0

  for arg in "$@"; do
    case $arg in
      -4) families=4; family_forced=1 ;;
      -6) families=6; family_forced=1 ;;
      -v|--verbose) CK_VERBOSE=1 ;;
      -h|--help)    usage; exit $EXIT_OK ;;
      -V|--version) version; exit $EXIT_OK ;;
      root|wurzn|juuri|ctif) select="$select $arg" ;;
      root.hagezi.org|wurzn.hagezi.org|juuri.hagezi.org|ctif.hagezi.org) select="$select ${arg%%.*}" ;;
      *) die_usage "unknown argument: $arg" ;;
    esac
  done

  command -v kdig >/dev/null 2>&1 || { install_hint; exit $EXIT_DEPS; }

  if [[ " $families " == *" 6 "* ]] && ! has_ipv6 2a01:4f8:c17:1c66::1; then
    if [ $family_forced = 1 ]; then
      echo "${C_RED}IPv6 is not available on this connection.${C_RESET}" >&2
      exit $EXIT_FAIL
    fi
    echo "${C_YELLOW}IPv6 is not available on this connection, skipping IPv6 tests.${C_RESET}"
    families=4
  fi

  echo "${C_BOLD}HaGeZi DNS check $VERSION${C_RESET}  ($(kdig -V 2>&1 | head -1))"
  echo

  while read -r name v4 v6 lbl <&3; do
    [ -z "$name" ] && continue
    if [ -n "$select" ]; then case " $select " in *" $name "*) ;; *) continue ;; esac; fi
    fqdn="$name.hagezi.org"
    for fam in $families; do
      if [ "$fam" = 4 ]; then ip=$v4; else ip=$v6; fi
      avg=$(ping_avg "$ip" "$fam")
      if [ -n "$avg" ]; then
        pingtxt="ping avg ${avg} ms"
        rank+="$avg $fqdn IPv$fam"$'\n'
      else
        pingtxt="ping n/a"
      fi
      echo "${C_BOLD}== $fqdn${C_RESET}  IPv$fam $ip  ($pingtxt)"
      for p in $CK_PROTOCOLS; do check_proto "$p" "$ip" "$fqdn" "$name"; done
      echo
    done
  done 3<<<"$HAGEZI_SERVERS"

  if [ -n "$rank" ]; then
    echo "${C_BOLD}Latency (average of $CK_PING_COUNT pings, lowest first):${C_RESET}"
    printf '%s' "$rank" | sort -n | awk '{printf "  %4d ms  %s %s\n", $1, $2, $3}'
    echo
  fi

  echo "${C_BOLD}Result:${C_RESET} ${C_GREEN}$CK_PASS passed${C_RESET}, ${C_RED}$CK_FAIL failed${C_RESET}, ${C_YELLOW}$CK_WARN warning(s)${C_RESET}, ${C_YELLOW}$CK_SKIP skipped${C_RESET}"
  if [ $CK_FAIL -gt 0 ]; then
    echo "A VPN or a router intercepting DNS can cause failures. Need help? support@hagezi.org"
    exit $EXIT_FAIL
  fi
  exit $EXIT_OK
}

case "${1:-}" in
  check)        shift; run_check "$@" ;;
  -V|--version) version; exit $EXIT_OK ;;
  *)            run_perf "$@" ;;
esac
