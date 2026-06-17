#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

# ==============================================================================
# Initialization & Dependency Checks
# ==============================================================================

if command -v drill >/dev/null 2>&1; then
  dig_cmd="drill"
elif command -v dig >/dev/null 2>&1; then
  dig_cmd="dig"
else
  echo "error: dig/drill was not found. Please install dnsutils or ldns." >&2
  exit 1
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

# ==============================================================================
# Configuration
# ==============================================================================

PROVIDERSV4="
8.8.8.8#Google
188.34.161.210#HaGeZi-Root
159.69.155.94#HaGeZi-Wurzn
45.90.28.0#NextDNS
86.54.11.11#DNS4EU
"

PROVIDERSV6="
2001:4860:4860::8888#Google-v6
2a01:4f8:c17:1c66::1#HaGeZi-Root-v6
2a01:4f8:1c1c:d363::1#HaGeZi-Wurzn-v6
2a07:a8c0::#NextDNS-v6
2a13:1001::86:54:11:11#DNS4EU-v6
"

DOMAINS2TEST=(google.com youtube.com facebook.com github.com instagram.com whatsapp.com reddit.com wikipedia.org amazon.com tiktok.com)
totaldomains=${#DOMAINS2TEST[@]}

# ==============================================================================
# Helper Functions
# ==============================================================================

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
  if $dig_cmd +short +tries=1 +time=2 +stats @2a0d:2a00:1::1 www.google.com 2>/dev/null | grep -q "216.239.38.120"; then
    echo "true"
  fi
}

# Fetch user public IPs and ISP/ASN in background to speed up execution
fetch_user_ips() {
  local v4="Not available" v4_info="Not available"
  local v6="Not available" v6_info="Not available"
  
  v4=$(curl -s -m 2 https://myipv4.addr.tools/plain 2>/dev/null || true)
  if [[ -n "$v4" ]]; then
    v4_info=$(curl -s -m 2 "ipinfo.io/${v4}/org" 2>/dev/null || true)
    [[ -z "$v4_info" ]] && v4_info="Not available"
  else
    v4="Not available"
  fi

  v6=$(curl -s -m 2 https://myipv6.addr.tools/plain 2>/dev/null || true)
  if [[ -n "$v6" ]]; then
    v6_info=$(curl -s -m 2 "ipinfo.io/${v6}/org" 2>/dev/null || true)
    [[ -z "$v6_info" ]] && v6_info="Not available"
  else
    v6="Not available"
  fi

  echo "$v4|$v4_info|$v6|$v6_info" > "$TMP_DIR/user_ips.txt"
}

# ==============================================================================
# Core Testing Logic
# ==============================================================================

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

  for d in "${DOMAINS2TEST[@]}"; do
    local ttime
    ttime=$($dig_cmd +tries=1 +time=2 +stats @"$pip" "$d" 2>/dev/null | awk '/Query time:/ {print $4; exit}' || true)
    
    [[ -z "$ttime" ]] && ttime=1000
    [[ "$ttime" == "0" ]] && ttime=1
    
    row="${row}|${ttime}"
    ((ftime += ttime))
  done

  local avg
  avg=$(awk -v ftime="$ftime" -v total="$totaldomains" 'BEGIN {printf "%.2f", ftime/total}')
  row="${row}|${avg}"

  local dnssec="No" chk_valid chk_bad
  chk_valid=$($dig_cmd +short +tries=1 +time=2 @"$pip" test.dnscheck.tools A 2>/dev/null || true)
  
  if [[ -n "$chk_valid" ]]; then
    chk_bad=$($dig_cmd +short +tries=1 +time=2 @"$pip" badsig.test.dnscheck.tools A 2>/dev/null || true)
    [[ -z "$chk_bad" ]] && dnssec="Yes"
  else
    dnssec="Err"
  fi
  row="${row}|${dnssec}"

  local audit_fails
  audit_fails=$(run_dnssec_audit_silent "$pip")
  if [[ -n "$audit_fails" ]]; then
    printf "Security vulnerability in \033[33m%s\033[0m (%s):\n%s\n" "$pname" "$pip" "$audit_fails" > "$TMP_DIR/${pip}_audit.txt"
  fi

  echo "$row" > "$TMP_DIR/${pip}.res"
}

# ==============================================================================
# Output Formatting
# ==============================================================================

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
  echo "- IPv4: $my_ipv4 (ISP: $my_ipv4_info)"
  echo "- IPv6: $my_ipv6 (ISP: $my_ipv6_info)" 
  echo ""

  printf "\033[1m%-16s %-24s\e[0m" "Provider" "IP"
  for ((i=1; i<=totaldomains; i++)); do printf "\e[1m%-8s\e[0m" "Test$i"; done
  printf "\033[1m%-8s %-7s\e[0m\n" "Average" "DNSSEC"

  while IFS= read -r row; do
    [[ -z "$row" ]] && continue
    IFS='|' read -r -a parts <<< "$row"
    
    printf "%-16s %-24s" "${parts[0]}" "${parts[1]}"
    for ((i=1; i<=totaldomains; i++)); do printf "%-8s" "${parts[i+1]}ms"; done
    printf "%-8s " "${parts[totaldomains+2]}"
    
    local dnssec_val="${parts[totaldomains+3]}"
    case "$dnssec_val" in
      *Yes*) printf "\e[32m%s\e[0m\n" "$dnssec_val" ;;
      *No*)  printf "\e[31m%s\e[0m\n" "$dnssec_val" ;;
      *)     printf "%s\n" "$dnssec_val" ;;
    esac
  done < <(echo "$rows" | sort_rows)

  local audit_files=("$TMP_DIR"/*_audit.txt)
  if [[ -e "${audit_files[0]}" ]]; then
    printf "\n\033[1m--- DNSSEC Audit Failures ---\033[0m\n"
    cat "$TMP_DIR"/*_audit.txt
  else
    printf "\nGreat! All DNS responses were successfully authenticated using DNSSEC.\n\n"
    printf "%-15s \e[32mPASS\e[0m\n" "ECDSA P-256"
    printf "%-15s \e[32mPASS\e[0m\n" "ECDSA P-384"
    printf "%-15s \e[32mPASS\e[0m\n" "Ed25519"
    printf "\n"
  fi
}

print_csv() {
  printf "provider,ip"
  for ((i=1; i<=totaldomains; i++)); do printf ",test%d" "$i"; done
  printf ",average,dnssec\n"
  while IFS= read -r row; do 
    [[ -n "$row" ]] && echo "${row//|/,}"
  done < <(echo "$rows" | sort_rows)
}

print_tsv() {
  printf "provider\tip"
  for ((i=1; i<=totaldomains; i++)); do printf "\ttest%d" "$i"; done
  printf "\taverage\tdnssec\n"
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
    printf '],"average":%s,"dnssec":"%s"}' "${parts[totaldomains+2]}" "${parts[totaldomains+3]}"
  done < <(echo "$rows" | sort_rows)
  printf '\n]\n'
}

# ==============================================================================
# Main Execution
# ==============================================================================

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

# Start IP check in background immediately to save execution time
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