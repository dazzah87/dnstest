#!/usr/bin/env bash

set -euo pipefail
export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

TMP_DIR=$(mktemp -d)
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

# Dependency Checks

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

PROVIDERSV4="
1.1.1.1#Cloudflare
8.8.8.8#Google
9.9.9.9#Quad9
86.54.11.11#DNS4EU
159.69.155.94#HaGeZi-Wurzn
188.34.161.210#HaGeZi-Root
217.237.150.205#Telekom
"

PROVIDERSV6="
2606:4700:4700::1111#Cloudflare-v6
2001:4860:4860::8888#Google-v6
2620:fe::fe#Quad9-v6
2a13:1001::86:54:11:11#DNS4EU-v6
2a01:4f8:1c1c:d363::1#HaGeZi-Wurzn-v6
2a01:4f8:c17:1c66::1#HaGeZi-Root-v6
2003:180:2:a000::53#Telekom-v6
"

DOMAINS2TEST=(amazon.de apple.com cloudflare.com denic.de facebook.com google.com microsoft.com paypal.com tiktok.com wikipedia.org)
totaldomains=${#DOMAINS2TEST[@]}

usage() {
  cat <<'EOF'
Usage:
  dnstest.sh [ipv4|ipv6|all] [table|csv|tsv|json] [--sort fastest|slowest]

Examples:
  dnstest.sh
  dnstest.sh all csv --sort slowest

Defaults:
  mode   = ipv4
  format = table
  sort   = fastest
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
  local ftime=0
  
  local row="${pname}|${pip}"

  # 1. Performance Tests
  for d in "${DOMAINS2TEST[@]}"; do
    local ttime
    ttime=$($dig_cmd +tries=1 +time=2 +stats @"$pip" "$d" 2>/dev/null | awk '/Query time:/ {print $4; exit}' || true)
    
    ttime=$(echo "$ttime" | tr -dc '0-9')
    [[ -z "$ttime" ]] && ttime=1000
    [[ "$ttime" == "0" ]] && ttime=1
    
    row="${row}|${ttime}"
    ((ftime += ttime))
  done

  # 2. Calculate Average
  local avg
  avg=$(awk -v ftime="$ftime" -v total="$totaldomains" 'BEGIN {printf "%.2f", ftime/total}')
  row="${row}|${avg}"

  # 3. ECS Check (EDNS Client Subnet)
  local ecs_check
  ecs_check=$($dig_cmd +short +tries=1 +time=2 @"$pip" o-o.myaddr.l.google.com TXT 2>/dev/null || true)
  local ecs="Strict"
  if echo "$ecs_check" | grep -qi "edns0-client-subnet"; then
    ecs="Sent"
  fi
  row="${row}|${ecs}"

  # 4. DNSSEC Audit
  local audit_fails
  audit_fails=$(run_dnssec_audit_silent "$pip")
  if [[ -n "$audit_fails" ]]; then
    printf "Security vulnerability in \033[33m%s\033[0m (%s):\n%s\n" "$pname" "$pip" "$audit_fails" > "$TMP_DIR/${pip}_audit.txt"
  fi

  echo "$row" > "$TMP_DIR/${pip}.res"
}

# Output Formatting

sort_rows() {
  local col_idx=$((totaldomains + 3))
  if [[ "$sort_mode" == "fastest" ]]; then
    sort -t '|' -k"${col_idx},${col_idx}n"
  else
    sort -t '|' -k"${col_idx},${col_idx}nr"
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

  local max_prov_len=8
  local max_ip_len=2
  local min_avg=999999
  local best_provider=""
  
  while IFS= read -r row; do
    [[ -z "$row" ]] && continue
    IFS='|' read -r -a parts <<< "$row"
    
    [[ ${#parts[0]} -gt max_prov_len ]] && max_prov_len=${#parts[0]}
    [[ ${#parts[1]} -gt max_ip_len ]] && max_ip_len=${#parts[1]}
    
    local avg="${parts[totaldomains+2]}"
    local is_less
    is_less=$(awk -v a="$avg" -v b="$min_avg" 'BEGIN{print (a < b) ? 1 : 0}')
    if [[ "$is_less" -eq 1 ]]; then
      min_avg="$avg"
      best_provider="${parts[0]}"
    fi
  done <<< "$rows"
  
  local prov_pad=$((max_prov_len + 2))
  local ip_pad=$((max_ip_len + 2))

  printf "\033[1m%-${prov_pad}s %-${ip_pad}s\e[0m" "Provider" "IP"
  for ((i=1; i<=totaldomains; i++)); do printf "\e[1m%-8s\e[0m" "Test$i"; done
  printf "\033[1m%-8s %-8s\e[0m\n" "Average" "Privacy"

  while IFS= read -r row; do
    [[ -z "$row" ]] && continue
    IFS='|' read -r -a parts <<< "$row"
    
    local c_start="" c_end="\e[0m"
    if [[ "${parts[0]}" == "$best_provider" ]]; then
      c_start="\e[36m"
    fi
    
    local ecs_val="${parts[totaldomains+3]}"
    local c_ecs=""
    if [[ "$ecs_val" == "Strict" ]]; then
      c_ecs="\e[32m" # Green
    else
      c_ecs="\e[33m" # Yellow
    fi
    
    printf "${c_start}%-${prov_pad}s %-${ip_pad}s" "${parts[0]}" "${parts[1]}"
    for ((i=1; i<=totaldomains; i++)); do printf "%-8s" "${parts[i+1]}ms"; done
    printf "%-8s ${c_ecs}%-8s${c_end}\n" "${parts[totaldomains+2]}" "$ecs_val"
  done < <(echo "$rows" | sort_rows)

  if ls "$TMP_DIR"/*_audit.txt 1> /dev/null 2>&1; then
    printf "\n\033[1m--- DNSSEC Audit Failures ---\033[0m\n"
    cat "$TMP_DIR"/*_audit.txt
  else
    printf "\nGreat! All DNS responses were successfully authenticated using DNSSEC:\n\n"
    printf "%-20s%-16s%-16s%s\n" "" "ECDSA P-256" "ECDSA P-384" "Ed25519"
    printf "%-20s\e[32mPASS\e[0m            \e[32mPASS\e[0m            \e[32mPASS\e[0m\n" "Valid signature"
    printf "%-20s\e[32mPASS\e[0m            \e[32mPASS\e[0m            \e[32mPASS\e[0m\n" "Invalid signature"
    printf "%-20s\e[32mPASS\e[0m            \e[32mPASS\e[0m            \e[32mPASS\e[0m\n" "Expired signature"
    printf "%-20s\e[32mPASS\e[0m            \e[32mPASS\e[0m            \e[32mPASS\e[0m\n" "Missing signature"
  fi

  printf "\n\033[1m--- Info ---\033[0m\n"
  printf "'Strict' = No ECS (EDNS Client Subnet) information is sent.\n"
  printf "'Sent' = Part of your client subnet is shared via ECS.\n\n"
}

print_csv() {
  printf "provider,ip"
  for ((i=1; i<=totaldomains; i++)); do printf ",test%d" "$i"; done
  printf ",average,privacy\n"
  while IFS= read -r row; do 
    [[ -n "$row" ]] && echo "${row//|/,}"
  done < <(echo "$rows" | sort_rows)
}

print_tsv() {
  printf "provider\tip"
  for ((i=1; i<=totaldomains; i++)); do printf "\ttest%d" "$i"; done
  printf "\taverage\tprivacy\n"
  while IFS= read -r row; do 
    [[ -n "$row" ]] && printf '%s\n' "$row" | tr '|' '\t'
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
      printf '%s' "${parts[i+1]}"
    done
    printf '],"average":%s,"privacy":"%s"}' "${parts[totaldomains+2]}" "${parts[totaldomains+3]}"
  done < <(echo "$rows" | sort_rows)
  printf '\n]\n'
}

# Main Execution

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

case "$format" in
  table) print_table ;;
  csv)   print_csv ;;
  tsv)   print_tsv ;;
  json)  print_json ;;
esac

exit 0
