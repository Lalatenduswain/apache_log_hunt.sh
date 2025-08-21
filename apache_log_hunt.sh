#!/usr/bin/env bash
# Apache Log Hunt – CentOS/RHEL httpd-focused scanner
# Finds suspicious requests (SQLi, XSS, LFI/RFI, command injection, auth abuse)
# Works with rotated .log and .log.gz files

set -euo pipefail

# ------------ Config / CLI ------------
LOG_DIR_DEFAULT="/var/log/httpd"    # CentOS/RHEL httpd default
LOG_DIR="${LOG_DIR_DEFAULT}"
OUT="/tmp/apache_log_audit_$(date +%F_%H-%M-%S).log"
MINUTES=0                            # 0 = all time (from logs). Set e.g. -m 120 for last 2h
ATTACKER_IPS=""                      # comma-separated: e.g. -a "54.179.156.222,3.10.160.87"
ONLY_TODAY=0

usage() {
  cat <<EOF
Usage: $0 [-d LOG_DIR] [-o OUTFILE] [-m MINUTES] [-a ip1,ip2,...] [--today]
  -d    Log directory (default: ${LOG_DIR_DEFAULT})
  -o    Output file (default: /tmp/apache_log_audit_YYYY-MM-DD_HH-MM-SS.log)
  -m    Only include events in the last MINUTES (requires GNU awk)
  -a    Comma-separated list of IPs to highlight
  --today  Only include today's entries (simple filter; access log format)
EOF
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) LOG_DIR="$2"; shift 2;;
    -o) OUT="$2"; shift 2;;
    -m) MINUTES="$2"; shift 2;;
    -a) ATTACKER_IPS="$2"; shift 2;;
    --today) ONLY_TODAY=1; shift;;
    -h|--help) usage;;
    *) echo "Unknown arg: $1"; usage;;
  esac
done

mkdir -p "$(dirname "$OUT")"

# ------------ Helpers ------------
have() { command -v "$1" >/dev/null 2>&1; }

# zgrep wrapper (falls back to grep for plain logs)
zg() {
  # usage: zg [grep args] -- file...
  # auto-select zgrep for *.gz else grep
  local args=()
  while [[ "$1" != "--" ]]; do args+=("$1"); shift; done
  shift # --
  local file
  for file in "$@"; do
    if [[ "$file" == *.gz ]]; then
      zgrep "${args[@]}" "$file"
    else
      grep "${args[@]}" "$file"
    fi
  done
}

# Build a time filter for access_log combined format: [dd/Mon/yyyy:HH:MM:SS zone]
# Uses gawk mktime for accurate filtering when -m is used.
build_time_filter() {
  [[ "$MINUTES" -eq 0 ]] && return 0
  if ! have gawk; then
    echo "[!] -m requires gawk; continuing without time filter." >&2
    MINUTES=0
    return 0
  fi
}

# ------------ Patterns ------------
# Core suspicious regex (case-insensitive) for access logs (URI & querystring)
# NOTE: keep as one ERE; some parts URL-encoded variants included
SUSPECT_RE='
(%27|%22|["'\''])\s*(or|and)\s*1\s*=\s*1|
union(\+|%20)+select|
information_schema|
sleep\([0-9]+\)|
benchmark\([0-9]+,|
load_file\(|into(\+|%20)+outfile|
%3Cscript%3E|<script>|onerror=|alert\(|document\.cookie|
\.\./|%2e%2e%2f|etc/passwd|/proc/self/environ|/proc/version|
php://(input|filter|fd)|data://|file://|expect://|
wget(\+|%20)|curl(\+|%20)|/bin/(sh|bash)|;|&&|`|
\{\{[^}]*\}\}|\$\{[^}]*\}|
(%3B|%26%26)|
(\b)(select|insert|update|delete|drop|truncate)(\b)(\+|%20)|
\blimit(\+|%20)+[0-9]+|
/wp-login\.php|/xmlrpc\.php|/administrator/|/user/login|
/\.git/|/\.env|/server-status
'

# Error log keywords (broad)
ERROR_RE='timeout|timed out|script timed out|end of script output before headers|broken pipe|too many connections|maximum execution time|connection reset|segmentation fault|AH\d+|client denied|invalid uri|script not found|permission denied|mod_security|SQL|injection|unauthorized|forbidden|attack|login failed'

# ------------ File sets ------------
mapfile -t ACCESS_LOGS < <(ls -1 ${LOG_DIR}/*access*.log* 2>/dev/null || true)
mapfile -t ERROR_LOGS  < <(ls -1 ${LOG_DIR}/*error*.log*  2>/dev/null || true)

if [[ ${#ACCESS_LOGS[@]} -eq 0 && ${#ERROR_LOGS[@]} -eq 0 ]]; then
  echo "No Apache logs found under $LOG_DIR" >&2
  exit 2
fi

# ------------ Output Header ------------
{
  echo "==== Apache Log Audit ($(date -u)) ===="
  echo "Host       : $(hostname -f || hostname)"
  echo "Log Dir    : $LOG_DIR"
  echo "Time Window: $([[ $MINUTES -gt 0 ]] && echo "last ${MINUTES} minutes" || echo "ALL")"
  [[ -n "$ATTACKER_IPS" ]] && echo "Focus IPs  : $ATTACKER_IPS"
  echo "==================================================="
} > "$OUT"

build_time_filter

# ------------ Functions ------------
filter_access_by_time() {
  # If MINUTES=0 and ONLY_TODAY=0 -> cat all
  if [[ "$MINUTES" -eq 0 && "$ONLY_TODAY" -eq 0 ]]; then
    cat --
    return
  fi

  if have gawk; then
    local cutoff_epoch=""
    if [[ "$MINUTES" -gt 0 ]]; then
      cutoff_epoch=$(date +%s -d "-${MINUTES} minutes")
    else
      # midnight today
      cutoff_epoch=$(date -d "00:00" +%s)
    fi

    gawk -v CUTOFF="$cutoff_epoch" '
      function mon2num(m){return (index("JanFebMarAprMayJunJulAugSepOctNovDec", m)+2)/3}
      match($0, /\[([0-9]{2})\/([A-Za-z]{3})\/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2}) [+-][0-9]{4}\]/, t){
        # mktime expects localtime; assume logs are local server time
        ts=mktime(sprintf("%04d %02d %02d %02d %02d %02d", t[3], mon2num(t[2]), t[1], t[4], t[5], t[6]))
        if (ts>=CUTOFF) print $0
        next
      }
      { if ('"$ONLY_TODAY"'==0) print $0 }'
  else
    # Fallback: crude today filter only (no minutes)
    if [[ "$ONLY_TODAY" -eq 1 ]]; then
      local today
      today=$(date +"%d/%b/%Y")
      grep "\[$today:"
    else
      cat --
    fi
  fi
}

# ------------ Scans ------------
{
  echo
  echo "--- ERROR LOGS: suspicious/error keywords ---"
  if [[ ${#ERROR_LOGS[@]} -eq 0 ]]; then
    echo "(no error logs found)"
  else
    zg -i -E -- "$ERROR_RE" "${ERROR_LOGS[@]}" || true
  fi

  echo
  echo "--- ACCESS LOGS: HTTP 4xx/5xx ---"
  if [[ ${#ACCESS_LOGS[@]} -eq 0 ]]; then
    echo "(no access logs found)"
  else
    zg -h -E -- 'HTTP/1\.[01]" [45][0-9]{2}' "${ACCESS_LOGS[@]}" \
    | filter_access_by_time
  fi

  echo
  echo "--- ACCESS LOGS: suspicious patterns (SQLi/XSS/LFI/RFI/CI) ---"
  if [[ ${#ACCESS_LOGS[@]} -eq 0 ]]; then
    echo "(no access logs found)"
  else
    zg -h -i -E -- "$SUSPECT_RE" "${ACCESS_LOGS[@]}" \
    | filter_access_by_time
  fi

  echo
  echo "--- TOP offending IPs by 4xx/5xx (Top 20) ---"
  zg -h -E -- 'HTTP/1\.[01]" [45][0-9]{2}' "${ACCESS_LOGS[@]}" 2>/dev/null \
  | filter_access_by_time \
  | awk '{print $1}' | sort | uniq -c | sort -nr | head -20

  echo
  echo "--- TOP suspicious URIs (from suspect matches, Top 20) ---"
  zg -h -i -E -- "$SUSPECT_RE" "${ACCESS_LOGS[@]}" 2>/dev/null \
  | filter_access_by_time \
  | awk -F\" '{print $2}' | awk '{print $2}' | sort | uniq -c | sort -nr | head -20

  echo
  echo "--- TOP User-Agents seen in 4xx/5xx (Top 15) ---"
  zg -h -E -- 'HTTP/1\.[01]" [45][0-9]{2}' "${ACCESS_LOGS[@]}" 2>/dev/null \
  | filter_access_by_time \
  | awk -F\" '{print $(NF)}' | sort | uniq -c | sort -nr | head -15

  if [[ -n "$ATTACKER_IPS" ]]; then
    echo
    echo "--- Focus IPs ---"
    IFS=',' read -r -a IPARR <<< "$ATTACKER_IPS"
    for ip in "${IPARR[@]}"; do
      ip_trim="${ip//[[:space:]]/}"
      echo
      echo "### $ip_trim : 4xx/5xx"
      zg -h -E -- "^[[:space:]]*${ip_trim}[[:space:]]" "${ACCESS_LOGS[@]}" 2>/dev/null \
      | filter_access_by_time \
      | awk -F\" '/HTTP\/1\.[01]"/ {print $0}' | awk '$9 ~ /^[45][0-9][0-9]$/ {print}'

      echo
      echo "### $ip_trim : suspicious matches"
      zg -h -i -E -- "$SUSPECT_RE" "${ACCESS_LOGS[@]}" 2>/dev/null \
      | filter_access_by_time \
      | awk -v ip="$ip_trim" '$1==ip {print}'
    done
  fi

  echo
  if have geoiplookup; then
    echo "--- GeoIP (Top 10 4xx/5xx IPs) ---"
    zg -h -E -- 'HTTP/1\.[01]" [45][0-9]{2}' "${ACCESS_LOGS[@]}" 2>/dev/null \
    | filter_access_by_time \
    | awk '{print $1}' | sort | uniq -c | sort -nr | head -10 \
    | while read -r cnt ip; do
        loc=$(geoiplookup "$ip" 2>/dev/null | awk -F': ' '{print $2}')
        echo "$ip ($cnt) -> $loc"
      done
  else
    echo "[i] GeoIP skipped (geoiplookup not installed)"
  fi

} >> "$OUT"

echo "Scan complete. Results saved to: $OUT"
