#!/usr/bin/env bash
set -euo pipefail

LC_ALL=C

ROOT_DIR=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT_DIR"

RUNS=${RUNS:-1}
BENCH_FILE_SIZE_MIB=${BENCH_FILE_SIZE_MIB:-1536}
BENCH_PROFILE=${BENCH_PROFILE:-large-1536mib}
BENCH_CHUNK_SIZE=${BENCH_CHUNK_SIZE:-1024}
BENCH_SERVER_BIN=${BENCH_SERVER_BIN:-_build/default/examples/eio/eio_h3_echo_server.exe}
BENCH_BUILD=${BENCH_BUILD:-1}
BENCH_PORT_BASE=${BENCH_PORT_BASE:-4600}
BENCH_OUTPUT_DIR=${BENCH_OUTPUT_DIR:-$(mktemp -d -t ocaml-quic-bench.XXXXXX)}
BENCH_SCENARIOS=${BENCH_SCENARIOS:-h3_upload_curl,h3_download_curl}

mkdir -p "$BENCH_OUTPUT_DIR"

if ! curl --help all 2>/dev/null | grep -q -- '--http3-only'; then
  echo 'curl in this environment does not support --http3-only' >&2
  exit 1
fi

if [ "$BENCH_CHUNK_SIZE" -lt 1 ] || [ "$BENCH_CHUNK_SIZE" -gt 1024 ]; then
  echo "BENCH_CHUNK_SIZE must be in 1..1024" >&2
  exit 1
fi

if [ "$BENCH_BUILD" = "1" ]; then
  dune build --profile=release examples/eio/eio_h3_echo_server.exe >/dev/null
fi

if [ ! -x "$BENCH_SERVER_BIN" ]; then
  echo "missing benchmark server binary: $BENCH_SERVER_BIN" >&2
  exit 1
fi

payload_size_bytes() {
  local path=$1
  if stat -c %s "$path" >/dev/null 2>&1; then
    stat -c %s "$path"
  elif stat -f %z "$path" >/dev/null 2>&1; then
    stat -f %z "$path"
  else
    wc -c < "$path" | tr -d ' '
  fi
}

create_payload() {
  local path=$1
  local size_mib=$2
  local size_bytes=$((size_mib * 1024 * 1024))
  if truncate -s "${size_bytes}" "$path" 2>/dev/null; then
    return 0
  fi
  if fallocate -l "${size_bytes}" "$path" 2>/dev/null; then
    return 0
  fi
  dd if=/dev/zero of="$path" bs=1048576 count="$size_mib" status=none
}

PAYLOAD="$BENCH_OUTPUT_DIR/payload.bin"
create_payload "$PAYLOAD" "$BENCH_FILE_SIZE_MIB"
PAYLOAD_SIZE_BYTES=$(payload_size_bytes "$PAYLOAD")

cleanup() {
  if [ -n "${SERVER_PID:-}" ]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_for_server() {
  local log_file=$1
  local tries=0
  while [ $tries -lt 100 ]; do
    if grep -q 'listening on UDP' "$log_file" 2>/dev/null; then
      return 0
    fi
    if [ -n "${SERVER_PID:-}" ] && ! kill -0 "$SERVER_PID" 2>/dev/null; then
      echo 'benchmark server exited before becoming ready' >&2
      tail -n 100 "$log_file" >&2 || true
      return 1
    fi
    sleep 0.1
    tries=$((tries + 1))
  done
  echo 'timed out waiting for benchmark server readiness' >&2
  tail -n 100 "$log_file" >&2 || true
  return 1
}

median_from_file() {
  local file=$1
  sort -n "$file" | awk '
    { values[NR] = $1 }
    END {
      if (NR == 0) exit 1;
      if (NR % 2 == 1) print values[(NR + 1) / 2];
      else printf "%.6f\n", (values[NR / 2] + values[(NR / 2) + 1]) / 2;
    }'
}

min_from_file() {
  sort -n "$1" | head -n 1
}

max_from_file() {
  sort -n "$1" | tail -n 1
}

run_scenario() {
  local scenario=$1
  local port=$2
  local server_mode=$3
  local curl_mode=$4
  local curl_url=$5

  local totals_file="$BENCH_OUTPUT_DIR/${scenario}.totals"
  local speeds_file="$BENCH_OUTPUT_DIR/${scenario}.speeds"
  : > "$totals_file"
  : > "$speeds_file"

  local run
  for run in $(seq 1 "$RUNS"); do
    echo "scenario=${scenario} run=${run}/${RUNS} port=${port}" >&2
    cleanup
    local server_log="$BENCH_OUTPUT_DIR/${scenario}.server.run${run}.log"
    local curl_log="$BENCH_OUTPUT_DIR/${scenario}.curl.run${run}.log"
    case "$server_mode" in
      upload)
        "$BENCH_SERVER_BIN" -p "$port" -upload-out /dev/null -chunk-size "$BENCH_CHUNK_SIZE" >"$server_log" 2>&1 &
        ;;
      download)
        "$BENCH_SERVER_BIN" -p "$port" -serve-file "$PAYLOAD" -chunk-size "$BENCH_CHUNK_SIZE" >"$server_log" 2>&1 &
        ;;
      *)
        echo "unknown server mode: $server_mode" >&2
        exit 1
        ;;
    esac
    SERVER_PID=$!
    wait_for_server "$server_log"

    local curl_output
    local curl_status
    set +e
    case "$curl_mode" in
      upload)
        curl_output=$(curl --http3-only -k -sS -o /dev/null \
          -X POST --data-binary "@$PAYLOAD" \
          -w 'total=%{time_total} speed=%{speed_upload}\n' \
          "$curl_url" 2>"$curl_log")
        curl_status=$?
        ;;
      download)
        curl_output=$(curl --http3-only -k -sS -o /dev/null \
          -w 'total=%{time_total} speed=%{speed_download}\n' \
          "$curl_url" 2>"$curl_log")
        curl_status=$?
        ;;
      *)
        set -e
        echo "unknown curl mode: $curl_mode" >&2
        exit 1
        ;;
    esac
    set -e
    if [ "$curl_status" -ne 0 ]; then
      echo "curl failed: scenario=${scenario} run=${run}/${RUNS} exit=${curl_status} url=${curl_url}" >&2
      echo "server_log=${server_log}" >&2
      echo "curl_log=${curl_log}" >&2
      echo "--- curl stderr (tail) ---" >&2
      tail -n 100 "$curl_log" >&2 || true
      echo "--- server log (tail) ---" >&2
      tail -n 200 "$server_log" >&2 || true
      return "$curl_status"
    fi

    local total
    local speed
    total=$(printf '%s\n' "$curl_output" | awk -F'[ =]' '/^total=/{print $2}')
    speed=$(printf '%s\n' "$curl_output" | awk -F'[ =]' '/^total=/{print $4}')
    printf '%s\n' "$total" >> "$totals_file"
    printf '%s\n' "$speed" >> "$speeds_file"

    cleanup
    SERVER_PID=
  done

  local median_total
  local median_speed_bps
  local min_total
  local max_total
  local min_speed_bps
  local max_speed_bps
  local median_speed_mib_s

  median_total=$(median_from_file "$totals_file")
  median_speed_bps=$(median_from_file "$speeds_file")
  min_total=$(min_from_file "$totals_file")
  max_total=$(max_from_file "$totals_file")
  min_speed_bps=$(min_from_file "$speeds_file")
  max_speed_bps=$(max_from_file "$speeds_file")
  median_speed_mib_s=$(awk -v bps="$median_speed_bps" 'BEGIN { printf "%.6f", bps / 1048576 }')

  local timestamp_utc
  timestamp_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  local commit_sha=${GITHUB_SHA:-$(git rev-parse HEAD)}
  local commit_short
  commit_short=$(printf '%s' "$commit_sha" | cut -c1-12)
  local branch_name=${GITHUB_REF_NAME:-$(git branch --show-current)}
  local workflow_run_id=${GITHUB_RUN_ID:-}
  local workflow_run_number=${GITHUB_RUN_NUMBER:-}
  local workflow_url=
  if [ -n "$workflow_run_id" ] && [ -n "${GITHUB_SERVER_URL:-}" ] && [ -n "${GITHUB_REPOSITORY:-}" ]; then
    workflow_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${workflow_run_id}"
  fi

  printf '{"timestamp_utc":"%s","commit_sha":"%s","commit_short":"%s","branch":"%s","benchmark_profile":"%s","scenario":"%s","runs":%s,"file_size_bytes":%s,"chunk_size_bytes":%s,"median_total_s":%s,"min_total_s":%s,"max_total_s":%s,"median_bytes_per_s":%s,"min_bytes_per_s":%s,"max_bytes_per_s":%s,"median_mib_per_s":%s,"runner_os":"%s","runner_arch":"%s","workflow_run_id":"%s","workflow_run_number":"%s","workflow_url":"%s"}\n' \
    "$timestamp_utc" \
    "$commit_sha" \
    "$commit_short" \
    "$branch_name" \
    "$BENCH_PROFILE" \
    "$scenario" \
    "$RUNS" \
    "$PAYLOAD_SIZE_BYTES" \
    "$BENCH_CHUNK_SIZE" \
    "$median_total" \
    "$min_total" \
    "$max_total" \
    "$median_speed_bps" \
    "$min_speed_bps" \
    "$max_speed_bps" \
    "$median_speed_mib_s" \
    "${RUNNER_OS:-}" \
    "${RUNNER_ARCH:-}" \
    "$workflow_run_id" \
    "$workflow_run_number" \
    "$workflow_url"
}

IFS=',' read -r -a scenarios <<< "$BENCH_SCENARIOS"

for scenario in "${scenarios[@]}"; do
  case "$scenario" in
    h3_upload_curl)
      run_scenario h3_upload_curl "$BENCH_PORT_BASE" upload upload "https://127.0.0.1:${BENCH_PORT_BASE}/upload"
      ;;
    h3_download_curl)
      run_scenario h3_download_curl "$((BENCH_PORT_BASE + 1))" download download "https://127.0.0.1:$((BENCH_PORT_BASE + 1))/file"
      ;;
    *)
      echo "unknown BENCH_SCENARIOS entry: $scenario" >&2
      exit 1
      ;;
  esac
done
