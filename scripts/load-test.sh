#!/usr/bin/env bash
# Lightweight concurrent load test for TrustSign endpoints.
# Usage examples:
#   ./scripts/load-test.sh
#   ./scripts/load-test.sh --url http://127.0.0.1:80/pki/health/performance --requests 500 --concurrency 50
#   ./scripts/load-test.sh --url http://127.0.0.1:80/pki/validate-token --method POST

set -euo pipefail

URL="http://127.0.0.1:80/pki/health/performance"
METHOD="GET"
REQUESTS=200
CONCURRENCY=20
CONNECT_TIMEOUT=5
TOTAL_TIMEOUT=20
HEADER_FILE=""
BODY_FILE=""
INSECURE="false"
WARMUP=10

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url)
      URL="$2"
      shift 2
      ;;
    --method)
      METHOD="$2"
      shift 2
      ;;
    --requests)
      REQUESTS="$2"
      shift 2
      ;;
    --concurrency)
      CONCURRENCY="$2"
      shift 2
      ;;
    --connect-timeout)
      CONNECT_TIMEOUT="$2"
      shift 2
      ;;
    --timeout)
      TOTAL_TIMEOUT="$2"
      shift 2
      ;;
    --headers)
      HEADER_FILE="$2"
      shift 2
      ;;
    --body)
      BODY_FILE="$2"
      shift 2
      ;;
    --insecure)
      INSECURE="true"
      shift
      ;;
    --warmup)
      WARMUP="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1"
      exit 1
      ;;
  esac
done

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required"
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required"
  exit 1
fi

if [[ -n "$HEADER_FILE" && ! -f "$HEADER_FILE" ]]; then
  echo "Header file not found: $HEADER_FILE"
  exit 1
fi

if [[ -n "$BODY_FILE" && ! -f "$BODY_FILE" ]]; then
  echo "Body file not found: $BODY_FILE"
  exit 1
fi

RESULT_FILE="$(mktemp)"
trap 'rm -f "$RESULT_FILE"' EXIT

build_header_args() {
  if [[ -z "$HEADER_FILE" ]]; then
    return 0
  fi
  while IFS= read -r line; do
    if [[ -z "$line" ]]; then
      continue
    fi
    printf -- "-H\n%s\n" "$line"
  done < "$HEADER_FILE"
}

run_request() {
  local response
  local -a cmd
  cmd=(curl -sS -o /dev/null -w "%{http_code} %{time_total}" -X "$METHOD" "$URL" --connect-timeout "$CONNECT_TIMEOUT" --max-time "$TOTAL_TIMEOUT")
  if [[ "$INSECURE" == "true" ]]; then
    cmd+=(-k)
  fi
  if [[ -n "$BODY_FILE" ]]; then
    cmd+=(--data-binary "@$BODY_FILE")
  fi
  if [[ -n "$HEADER_FILE" ]]; then
    while IFS= read -r line; do
      if [[ -z "$line" ]]; then
        continue
      fi
      cmd+=(-H "$line")
    done < "$HEADER_FILE"
  fi
  if ! response="$("${cmd[@]}" 2>/dev/null)"; then
    response="000 0"
  fi
  printf "%s\n" "$response" >> "$RESULT_FILE"
}

export -f run_request
export URL METHOD CONNECT_TIMEOUT TOTAL_TIMEOUT HEADER_FILE BODY_FILE INSECURE RESULT_FILE

if [[ "$WARMUP" -gt 0 ]]; then
  i=0
  while [[ "$i" -lt "$WARMUP" ]]; do
    run_request
    i=$((i + 1))
  done
fi

START_EPOCH="$(python3 - <<'PY'
import time
print(time.time())
PY
)"

seq 1 "$REQUESTS" | xargs -n1 -P "$CONCURRENCY" -I{} bash -lc 'run_request'

END_EPOCH="$(python3 - <<'PY'
import time
print(time.time())
PY
)"

python3 - "$RESULT_FILE" "$REQUESTS" "$CONCURRENCY" "$URL" "$START_EPOCH" "$END_EPOCH" <<'PY'
import math
import statistics
import sys

result_file = sys.argv[1]
requests = int(sys.argv[2])
concurrency = int(sys.argv[3])
url = sys.argv[4]
start_epoch = float(sys.argv[5])
end_epoch = float(sys.argv[6])

codes = []
latencies_ms = []
with open(result_file, "r", encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        code, seconds = parts
        try:
            codes.append(int(code))
            latencies_ms.append(float(seconds) * 1000.0)
        except ValueError:
            continue

def percentile(values, p):
    if not values:
        return 0.0
    s = sorted(values)
    idx = (len(s) - 1) * p
    lo = math.floor(idx)
    hi = math.ceil(idx)
    if lo == hi:
        return s[int(idx)]
    return s[lo] + (s[hi] - s[lo]) * (idx - lo)

ok = sum(1 for c in codes if 200 <= c < 400)
client_err = sum(1 for c in codes if 400 <= c < 500)
server_err = sum(1 for c in codes if c >= 500)
network_err = sum(1 for c in codes if c == 0)
elapsed = max(0.001, end_epoch - start_epoch)
rps = len(codes) / elapsed

print("=== TrustSign Load Test ===")
print(f"URL: {url}")
print(f"Requests scheduled: {requests}")
print(f"Responses captured: {len(codes)}")
print(f"Concurrency: {concurrency}")
print(f"Elapsed seconds: {elapsed:.3f}")
print(f"Throughput (req/s): {rps:.2f}")
print("")
print("Status counts:")
print(f"  2xx/3xx: {ok}")
print(f"  4xx:     {client_err}")
print(f"  5xx:     {server_err}")
print(f"  000:     {network_err}")
print("")
if latencies_ms:
    print("Latency (ms):")
    print(f"  min: {min(latencies_ms):.2f}")
    print(f"  p50: {percentile(latencies_ms, 0.50):.2f}")
    print(f"  p95: {percentile(latencies_ms, 0.95):.2f}")
    print(f"  p99: {percentile(latencies_ms, 0.99):.2f}")
    print(f"  max: {max(latencies_ms):.2f}")
    print(f"  avg: {statistics.mean(latencies_ms):.2f}")
else:
    print("No latency samples captured.")
PY
