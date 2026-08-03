#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

TMP_DIR=$(mktemp -d)
cleanup() {
  kill $(jobs -p) 2>/dev/null || true
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

if command -v drill >/dev/null 2>&1; then
  dig_cmd="drill"
elif command -v dig >/dev/null 2>&1; then
  dig_cmd="dig"
else
  echo "error: dig/drill was not found. Please install dnsutils (bind-tools) or ldns." >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "error: curl is required but not found. Please install curl." >&2
  exit 1
fi

TIMEOUT_SEC=2
REPEAT_COUNT=1

# Latency color thresholds in ms
THRESHOLD_GREEN=25
THRESHOLD_YELLOW=50
THRESHOLD_ORANGE=100

# ANSI color codes
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_ORANGE='\033[0;38;5;208m'
COLOR_RED='\033[0;31m'
COLOR_RESET='\033[0m'

PROVIDERSV4="
1.1.1.1#Cloudflare
8.8.8.8#Google
9.9.9.9#Quad9
86.54.11.1#DNS4EU
94.140.14.140#AdGuard-DNS
188.34.161.210#HaGeZi-Root
159.69.155.94#HaGeZi-Wurzn
"

PROVIDERSV6="
2606:4700:4700::1111#Cloudflare-v6
2001:4860:4860::8888#Google-v6
2620:fe::fe#Quad9-v6
2a13:1001::86:54:11:1#DNS4EU-v6
2a10:50c0::1:ff#AdGuard-DNS-v6
2a01:4f8:c17:1c66::1#HaGeZi-Root-v6
2a01:4f8:1c1c:d363::1#HaGeZi-Wurzn-v6
"

DOMAINS2TEST=(amazon.de apple.com cloudflare.com denic.de facebook.com google.com microsoft.com paypal.com tiktok.com wikipedia.org)
totaldomains=${#DOMAINS2TEST[@]}

usage() {
  cat <<'EOF'
Usage:
  dnsperftest.sh [ipv4|ipv6|all] [table|csv|tsv|json] [--sort fastest|slowest] [--repeat N]

Examples:
  dnsperftest.sh all table --repeat 3
  dnsperftest.sh ipv4 csv --sort slowest

Defaults:
  mode   = ipv4
  format = table
  sort   = fastest
  repeat = 1
EOF
}

check_ipv6_support() {
  if $dig_cmd +short +tries=1 +time=2 +stats @2a0d:2a00:1::1 www.google.com 2>/dev/null | grep -q "^216\.239\."; then
    echo "true"
  fi
}

fetch_user_ips() {
  local v4="Not available" v4_info="Not available"
  local v6="Not available" v6_info="Not available"
  
  local raw_v4
  raw_v4=$(curl -s -m 2 https://myipv4.addr.tools/plain 2>/dev/null | tr -dc '0-9.' || true)
  if [[ "$raw_v4" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    v4="$raw_v4"
    v4_info=$(curl -s -m 2 "https://ipinfo.io/${v4}/org" 2>/dev/null | sed -E 's/^AS[0-9]+[ ]*//' | tr -dc '[:print:]' || true)
    [[ -z "$v4_info" ]] && v4_info="Not available"
  fi

  local raw_v6
  raw_v6=$(curl -s -m 2 https://myipv6.addr.tools/plain 2>/dev/null | tr -dc 'a-fA-F0-9:' || true)
  if [[ -n "$raw_v6" && "$raw_v6" == *":"* && "$raw_v6" =~ ^[a-fA-F0-9:]+$ ]]; then
    v6="$raw_v6"
    v6_info=$(curl -s -m 2 "https://ipinfo.io/${v6}/org" 2>/dev/null | sed -E 's/^AS[0-9]+[ ]*//' | tr -dc '[:print:]' || true)
    [[ -z "$v6_info" ]] && v6_info="Not available"
  fi

  echo "$v4|$v4_info|$v6|$v6_info" > "$TMP_DIR/user_ips.txt"
}

run_dnssec_audit_silent() {
  local pip=$1
  local fails=""
  
  local tests=(
    "Valid signature:test:YES"
    "Invalid signature:badsig.test:NO"
    "Expired signature:expiredsig.test:NO"
    "Missing signature:nosig.test:NO"
  )
  local algos=("alg13:ECDSA P-256" "alg14:ECDSA P-384" "alg15:Ed25519")

  for t in "${tests[@]}"; do
    IFS=':' read -r test_name prefix expect <<< "$t"
    for a_info in "${algos[@]}"; do
      IFS=':' read -r a a_name <<< "$a_info"
      local domain="${prefix}-${a}.dnscheck.tools"
      
      local res status="FAIL"
      res=$($dig_cmd +short +tries=1 +time=2 @"$pip" "$domain" A 2>/dev/null || true)

      if [[ "$expect" == "YES" && -n "$res" ]] || [[ "$expect" == "NO" && -z "$res" ]]; then
        status="PASS"
      fi

      if [[ "$status" == "FAIL" ]]; then
        fails="${fails:+$fails$'\n'}  - $test_name ($a_name)"
      fi
    done
  done
  echo "$fails"
}

test_provider_worker() {
  local pip=$1 pname=$2
  local ftime=0 successcount=0
  local row="${pname}|${pip}"

  for d in "${DOMAINS2TEST[@]}"; do
    local dtime=0 dsuccess=0 dtimeout=0
    local r=1
    while [ "$r" -le "$REPEAT_COUNT" ]; do
      local output rc ttime
      set +e
      output=$(timeout "${TIMEOUT_SEC}s" "$dig_cmd" +tries=1 +time="$TIMEOUT_SEC" +stats @"$pip" "$d" 2>&1)
      rc=$?
      set -e

      ttime=$(printf '%s' "$output" | awk '/Query time:/ {print $4; exit}' || true)
      
      if [ "$rc" -eq 124 ]; then
        dtimeout=$((dtimeout + 1))
      elif [ -z "${ttime:-}" ]; then
        : 
      elif [ "$ttime" = "0" ]; then
        dtime=$((dtime + 1))
        dsuccess=$((dsuccess + 1))
      else
        dtime=$((dtime + ttime))
        dsuccess=$((dsuccess + 1))
      fi
      r=$((r + 1))
    done

    local result
    if [ "$dsuccess" -gt 0 ]; then
      if [ "$REPEAT_COUNT" -eq 1 ]; then
        result="$dtime"
      else
        result=$(awk -v t="$dtime" -v c="$dsuccess" 'BEGIN{printf "%.2f", t/c}')
      fi
      ftime=$(awk -v a="$ftime" -v b="$result" 'BEGIN{printf "%.4f", a+b}')
      successcount=$((successcount + 1))
    elif [ "$dtimeout" -gt 0 ]; then
      result="timeout"
    else
      result="error"
    fi
    row="${row}|${result}"
  done

  local avg sortkey
  if [ "$successcount" -gt 0 ]; then
    avg=$(awk -v f="$ftime" -v s="$successcount" 'BEGIN {printf "%.2f", f/s}')
    sortkey="$avg"
  else
    if printf '%s' "$row" | grep -q "|timeout"; then
      avg="timeout"
    else
      avg="error"
    fi
    sortkey="999999"
  fi
  row="${row}|${avg}"

  local ecs_check
  ecs_check=$($dig_cmd +short +tries=1 +time=2 @"$pip" o-o.myaddr.l.google.com TXT 2>/dev/null || true)
  local ecs="Strict"
  if echo "$ecs_check" | grep -qi "edns0-client-subnet"; then
    ecs="Sent"
  fi
  row="${row}|${ecs}|${sortkey}"

  local audit_fails
  audit_fails=$(run_dnssec_audit_silent "$pip")
  if [[ -n "$audit_fails" ]]; then
    printf "Security vulnerability in \033[33m%s\033[0m (%s):\n%s\n" "$pname" "$pip" "$audit_fails" > "$TMP_DIR/${pip}_audit.txt"
  fi

  echo "$row" > "$TMP_DIR/${pip}.res"
}

sort_rows() {
  local col_idx=$((totaldomains + 5))
  if [[ "$sort_mode" == "fastest" ]]; then
    sort -t '|' -k"${col_idx},${col_idx}n"
  else
    sort -t '|' -k"${col_idx},${col_idx}nr"
  fi
}

colorize_value() {
  local val="$1" unit="${2:-}"
  if [[ "$val" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    local is_green is_yellow is_orange
    is_green=$(awk -v v="$val" -v t="$THRESHOLD_GREEN" 'BEGIN{print (v <= t) ? 1 : 0}')
    is_yellow=$(awk -v v="$val" -v t="$THRESHOLD_YELLOW" 'BEGIN{print (v <= t) ? 1 : 0}')
    is_orange=$(awk -v v="$val" -v t="$THRESHOLD_ORANGE" 'BEGIN{print (v <= t) ? 1 : 0}')
    
    if [ "$is_green" -eq 1 ]; then printf '%b%s%s%b' "$COLOR_GREEN" "$val" "$unit" "$COLOR_RESET"
    elif [ "$is_yellow" -eq 1 ]; then printf '%b%s%s%b' "$COLOR_YELLOW" "$val" "$unit" "$COLOR_RESET"
    elif [ "$is_orange" -eq 1 ]; then printf '%b%s%s%b' "$COLOR_ORANGE" "$val" "$unit" "$COLOR_RESET"
    else printf '%b%s%s%b' "$COLOR_RED" "$val" "$unit" "$COLOR_RESET"; fi
  elif [ "$val" = "error" ] || [ "$val" = "timeout" ]; then
    printf '%b%s%b' "$COLOR_RED" "$val" "$COLOR_RESET"
  else
    printf '%s' "$val"
  fi
}

print_table() {
  local my_ipv4="Not available" my_ipv4_info="Not available"
  local my_ipv6="Not available" my_ipv6_info="Not available"
  if [[ -f "$TMP_DIR/user_ips.txt" ]]; then
    IFS='|' read -r my_ipv4 my_ipv4_info my_ipv6 my_ipv6_info < "$TMP_DIR/user_ips.txt"
  fi

  echo ""
  echo "Your public IP:"
  echo "- IPv4: $my_ipv4 ($my_ipv4_info)"
  echo "- IPv6: $my_ipv6 ($my_ipv6_info)" 
  echo ""

  local prov_pad=21 ip_pad=16
  printf "\033[1m%-${prov_pad}s %-${ip_pad}s\e[0m" "Provider" "IP"
  for ((i=1; i<=totaldomains; i++)); do printf "\e[1m%-10s\e[0m" "Test$i"; done
  printf "\033[1m%-10s %-8s\e[0m\n" "Average" "Privacy"

  while IFS= read -r row; do
    [[ -z "$row" ]] && continue
    IFS='|' read -r -a parts <<< "$row"
    
    local ecs_val="${parts[totaldomains+3]}"
    local c_ecs="\e[33m" # Yellow
    [[ "$ecs_val" == "Strict" ]] && c_ecs="\e[32m" # Green
    
    printf "%-${prov_pad}s %-${ip_pad}s" "${parts[0]}" "${parts[1]}"
    for ((i=1; i<=totaldomains; i++)); do
      val="${parts[i+1]}"
      display=$( [[ "$val" =~ ^[0-9]+([.][0-9]+)?$ ]] && echo "${val}ms" || echo "$val" )
      colored=$(colorize_value "$val" "ms")
      
      # Determine real padding (10 spaces minus display length)
      padlen=$((10 - ${#display}))
      [[ $padlen -lt 0 ]] && padlen=0
      printf "%b%*s" "$colored" "$padlen" ""
    done
    
    avgval="${parts[totaldomains+2]}"
    display_avg=$( [[ "$avgval" =~ ^[0-9]+([.][0-9]+)?$ ]] && echo "${avgval}ms" || echo "$avgval" )
    coloredavg=$(colorize_value "$avgval" "ms")
    padlen=$((10 - ${#display_avg}))
    [[ $padlen -lt 0 ]] && padlen=0

    printf "%b%*s ${c_ecs}%-8s\e[0m\n" "$coloredavg" "$padlen" "" "$ecs_val"
  done < <(echo "$rows" | sort_rows)

  if ls "$TMP_DIR"/*_audit.txt 1> /dev/null 2>&1; then
    printf "\n\033[1m--- DNSSEC Audit Failures ---\033[0m\n"
    cat "$TMP_DIR"/*_audit.txt
  else
    printf "\nGreat! All DNS responses were successfully authenticated using DNSSEC.\n"
  fi
}

print_csv() {
  printf "provider,ip"
  for ((i=1; i<=totaldomains; i++)); do printf ",test%d" "$i"; done
  printf ",average,privacy\n"
  while IFS= read -r row; do 
    [[ -n "$row" ]] || continue
    # Remove sortkey from output
    trimmed="${row%|*}"
    echo "${trimmed//|/,}"
  done < <(echo "$rows" | sort_rows)
}

print_tsv() {
  printf "provider\tip"
  for ((i=1; i<=totaldomains; i++)); do printf "\ttest%d" "$i"; done
  printf "\taverage\tprivacy\n"
  while IFS= read -r row; do 
    [[ -n "$row" ]] || continue
    trimmed="${row%|*}"
    printf '%s\n' "$trimmed" | tr '|' '\t'
  done < <(echo "$rows" | sort_rows)
}

print_json() {
  printf '[\n'
  local first=1
  while IFS= read -r row; do
    [[ -z "$row" ]] && continue
    IFS='|' read -r -a parts <<< "$row"
    
    [[ "$first" -eq 1 ]] || printf ',\n'
    first=0
    
    printf '  {"provider":"%s","ip":"%s","results":[' "${parts[0]}" "${parts[1]}"
    for ((i=1; i<=totaldomains; i++)); do
      [[ "$i" -eq 1 ]] || printf ','
      val="${parts[i+1]}"
      if [[ "$val" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        printf '%s' "$val"
      else
        printf '"%s"' "$val"
      fi
    done
    printf '],"average":"%s","privacy":"%s"}' "${parts[totaldomains+2]}" "${parts[totaldomains+3]}"
  done < <(echo "$rows" | sort_rows)
  printf '\n]\n'
}

mode="ipv4"
format="table"
sort_mode="fastest"

while [[ $# -gt 0 ]]; do
  case "$1" in
    ipv4|ipv6|all) mode="$1" ;;
    table|csv|tsv|json) format="$1" ;;
    --sort)
      shift
      [[ $# -gt 0 ]] || { echo "error: --sort requires a value" >&2; usage; exit 1; }
      case "$1" in
        fastest|slowest) sort_mode="$1" ;;
        *) echo "error: unsupported sort mode: $1" >&2; usage; exit 1 ;;
      esac
      ;;
    --repeat)
      shift
      [[ $# -gt 0 ]] || { echo "error: --repeat requires a value" >&2; usage; exit 1; }
      if [[ "$1" =~ ^[1-9][0-9]*$ ]]; then
        REPEAT_COUNT="$1"
      else
        echo "error: --repeat requires a positive integer >= 1" >&2; usage; exit 1
      fi
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage; exit 1 ;;
  esac
  shift
done

hasipv6=$(check_ipv6_support)

case "$mode" in
  ipv4) providerstotest="$PROVIDERSV4" ;;
  ipv6)
    [[ -n "$hasipv6" ]] || { echo "error: IPv6 support not found." >&2; exit 1; }
    providerstotest="$PROVIDERSV6"
    ;;
  all)
    if [[ -n "$hasipv6" ]]; then providerstotest="$PROVIDERSV4"$'\n'"$PROVIDERSV6"
    else providerstotest="$PROVIDERSV4"; fi
    ;;
esac

fetch_user_ips &

for p in $providerstotest; do
  [[ -z "$p" ]] && continue
  pip=${p%%#*}
  pname=${p##*#}
  [[ -z "$pname" ]] && pname="$pip"
  
  test_provider_worker "$pip" "$pname" &
done

wait

rows=$(cat "$TMP_DIR"/*.res 2>/dev/null || true)

[[ -z "$rows" ]] && { echo "error: all tested providers failed (error or timeout)." >&2; exit 2; }

case "$format" in
  table) print_table ;;
  csv)   print_csv ;;
  tsv)   print_tsv ;;
  json)  print_json ;;
esac

exit 0