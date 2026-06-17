#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

if command -v drill >/dev/null 2>&1; then
  dig_cmd="drill"
elif command -v dig >/dev/null 2>&1; then
  dig_cmd="dig"
else
  echo "error: dig was not found. Please install dnsutils." >&2
  exit 1
fi

usage() {
  cat <<'EOF2'
Usage:
  dnstest.sh [ipv4|ipv6|all] [table|csv|tsv|json] [--sort fastest|slowest]

Examples:
  dnstest.sh
  dnstest.sh all csv --sort slowest

Defaults:
  mode   = ipv4
  format = table
  sort   = fastest
EOF2
}

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

DOMAINS2TEST=(
  google.com
  youtube.com
  facebook.com
  github.com
  instagram.com
  whatsapp.com
  reddit.com
  wikipedia.org
  amazon.com
  tiktok.com
)
totaldomains=${#DOMAINS2TEST[@]}

mode="ipv4"
format="table"
sort_mode="fastest"

while [ $# -gt 0 ]; do
  case "$1" in
    ipv4|ipv6|all) mode="$1" ;;
    table|csv|tsv|json) format="$1" ;;
    --sort)
      shift
      [ $# -gt 0 ] || { echo "error: --sort requires a value" >&2; usage; exit 1; }
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

hasipv6=""
if $dig_cmd +short +tries=1 +time=2 +stats @2a0d:2a00:1::1 www.google.com 2>/dev/null | grep -q "216.239.38.120"; then
  hasipv6="true"
fi

case "$mode" in
  ipv4) providerstotest="$PROVIDERSV4" ;;
  ipv6)
    [ -n "$hasipv6" ] || { echo "error: IPv6 support not found." >&2; exit 1; }
    providerstotest="$PROVIDERSV6"
    ;;
  all)
    if [ -n "$hasipv6" ]; then providerstotest="$PROVIDERSV4"$'\n'"$PROVIDERSV6"
    else providerstotest="$PROVIDERSV4"; fi
    ;;
esac

rows=""
for p in $providerstotest; do
  [ -z "$p" ] && continue
  pip=${p%%#*}
  pname=${p##*#}
  [ -z "$pname" ] && pname="$pip"

  ftime=0
  row="$pname"

  for d in "${DOMAINS2TEST[@]}"; do
    ttime=$($dig_cmd +tries=1 +time=2 +stats @"$pip" "$d" 2>/dev/null | awk '/Query time:/ {print $4; exit}' || true)
    if [ -z "${ttime:-}" ]; then ttime=1000; elif [ "$ttime" = "0" ]; then ttime=1; fi
    row="${row}|${ttime}"
    ftime=$((ftime + ttime))
  done

  avg=$(awk -v ftime="$ftime" -v total="$totaldomains" 'BEGIN {printf "%.2f", ftime/total}')
  row="${row}|${avg}"

  dnssec="No"
  chk_valid=$($dig_cmd +short +tries=1 +time=2 @"$pip" test.dnscheck.tools A 2>/dev/null || true)
  if [ -n "$chk_valid" ]; then
    chk_bad=$($dig_cmd +short +tries=1 +time=2 @"$pip" badsig.test.dnscheck.tools A 2>/dev/null || true)
    if [ -z "$chk_bad" ]; then dnssec="Yes"; fi
  else
    dnssec="Err"
  fi
  row="${row}|${dnssec}"

  if [ -z "$rows" ]; then rows="$row"; else rows="${rows}"$'\n'"$row"; fi
done

sort_rows() {
  case "$sort_mode" in
    fastest) printf '%s\n' "$rows" | sort -t '|' -k"$((totaldomains + 2))","$((totaldomains + 2))"n ;;
    slowest) printf '%s\n' "$rows" | sort -t '|' -k"$((totaldomains + 2))","$((totaldomains + 2))"nr ;;
  esac
}

print_table() {
  echo ""
  my_ipv4=$(curl -s -m 2 https://myipv4.addr.tools/plain 2>/dev/null || echo "Not available")
  my_ipv6=$(curl -s -m 2 https://myipv6.addr.tools/plain 2>/dev/null || echo "Not available")

  echo "Your public IP:"
  echo "- IPv4: $my_ipv4"
  echo "- IPv6: $my_ipv6" 
  echo ""
  echo "Your DNS resolvers:"
  
  ipv4_resolver=$($dig_cmd +short -t A whoami.akamai.net 2>/dev/null | head -n1)
  ipv6_resolver=$($dig_cmd +short -t AAAA ipv6.test-ipv6.com 2>/dev/null | head -n1)

  if [ -n "$ipv4_resolver" ]; then
    ptr=$($dig_cmd +short -x "$ipv4_resolver" 2>/dev/null | tail -n 1 || echo "N/A")
    printf -- "- IPv4: %-38s (%s)\n" "$ipv4_resolver" "${ptr%.}"
  fi

  if [ -n "$ipv6_resolver" ]; then
    ptr=$($dig_cmd +short -x "$ipv6_resolver" 2>/dev/null | tail -n 1 || echo "N/A")
    printf -- "- IPv6: %-38s (%s)\n" "$ipv6_resolver" "${ptr%.}"
  fi

  if [ -z "$ipv4_resolver" ] && [ -z "$ipv6_resolver" ]; then
    echo "- Not available"
  fi
  
  echo ""

  printf "%-21s" "Provider"
  for ((i=1; i<=totaldomains; i++)); do printf "%-10s" "Test$i"; done
  printf "%-10s %-7s\n" "Average" "DNSSEC"

  while IFS= read -r row; do
    [ -z "$row" ] && continue
    IFS='|' read -r -a parts <<< "$row"
    printf "%-21s" "${parts[0]}"
    for ((i=1; i<=totaldomains; i++)); do printf "%-10s" "${parts[i]}ms"; done
    printf "%-10s " "${parts[totaldomains+1]}"
    dnssec_val="${parts[totaldomains+2]}"
    if [[ "$dnssec_val" == *"Yes"* ]]; then
        printf "\e[32m%s\e[0m\n" "$dnssec_val"
    elif [[ "$dnssec_val" == *"No"* ]]; then
        printf "\e[31m%s\e[0m\n" "$dnssec_val"
    else
        printf "%s\n" "$dnssec_val"
    fi
  done < <(sort_rows)
}

print_csv() {
  printf "provider"
  for ((i=1; i<=totaldomains; i++)); do printf ",test%d" "$i"; done
  printf ",average,dnssec\n"
  while IFS= read -r row; do [ -z "$row" ] && continue; printf "%s\n" "${row//|/,}"; done < <(sort_rows)
}

print_tsv() {
  printf "provider"
  for ((i=1; i<=totaldomains; i++)); do printf "\ttest%d" "$i"; done
  printf "\taverage\tdnssec\n"
  while IFS= read -r row; do [ -z "$row" ] && continue; printf "%s\n" "$(printf '%s' "$row" | tr '|' '\t')"; done < <(sort_rows)
}

print_json() {
  printf '[\n'
  first=1
  while IFS= read -r row; do
    [ -z "$row" ] && continue
    IFS='|' read -r -a parts <<< "$row"
    [ "$first" -eq 1 ] || printf ',\n'
    first=0
    printf '  {"provider":"%s","results":[' "${parts[0]}"
    for ((i=1; i<=totaldomains; i++)); do
      [ "$i" -eq 1 ] || printf ','
      printf '%s' "${parts[i]}"
    done
    printf '],"average":"%s","dnssec":"%s"}' "${parts[totaldomains+1]}" "${parts[totaldomains+2]}"
  done < <(sort_rows)
  printf '\n]\n'
}

run_dnssec_audit_silent() {
  local pip=$1
  local pname=$2
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
      domain="${prefix}-${a}.dnscheck.tools"
      
      res=$($dig_cmd +short +tries=1 +time=2 @"$pip" "$domain" A 2>/dev/null || true)

      status="FAIL"
      if [ "$expect" = "YES" ]; then
        if [ -n "$res" ]; then status="PASS"; fi
      else
        if [ -z "$res" ]; then status="PASS"; fi
      fi

      if [ "$status" = "FAIL" ]; then
        if [ -z "$fails" ]; then
          fails="  - $test_name ($a_name)"
        else
          fails+=$'\n'"  - $test_name ($a_name)"
        fi
      fi
    done
  done
  
  echo "$fails"
}

case "$format" in
  table) print_table ;;
  csv)   print_csv ;;
  tsv)   print_tsv ;;
  json)  print_json ;;
esac

if [ "$format" = "table" ]; then
  best_row=$(printf '%s\n' "$rows" | sort -t '|' -k"$((totaldomains + 2))","$((totaldomains + 2))"n | head -n 1)
  IFS='|' read -r -a best_parts <<< "$best_row"
  echo ""
  echo "Best DNS provider for your network: ${best_parts[0]}"
  echo ""

  has_any_failures=0

  for p in $providerstotest; do
    [ -z "$p" ] && continue
    pip=${p%%#*}
    pname=${p##*#}
    [ -z "$pname" ] && pname="$pip"
    
    provider_fails=$(run_dnssec_audit_silent "$pip" "$pname")
    
    if [ -n "$provider_fails" ]; then
       echo "Security vulnerability in $pname ($pip):"
       echo "$provider_fails"
       echo ""
       has_any_failures=1
    fi
  done

  if [ "$has_any_failures" -eq 0 ]; then
     echo "All DNS responses were successfully authenticated using DNSSEC (ECDSA P-256, ECDSA P-384 & Ed25519)."
     echo ""
  fi
fi

exit 0