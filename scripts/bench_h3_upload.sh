#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/bench_h3_upload.sh /path/to/file [output-dir]

Builds the Eio HTTP/3 echo server in release mode, starts it, runs a curl
HTTP/3 upload benchmark against /upload, and captures:

- server stderr log
- curl stdout/stderr
- a macOS `sample` profile, when available and `CAPTURE_SAMPLE!=0`
- a short text summary

Environment:
- `SKIP_BUILD=1` to skip rebuilding the server
- `CAPTURE_SAMPLE=0` to disable the macOS sampler during throughput runs
- `UPLOAD_OUT=/path/to/file` to make the benchmark server persist uploaded data
EOF
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 1
fi

FILE_PATH=$1
if [[ ! -f "$FILE_PATH" ]]; then
  echo "input file not found: $FILE_PATH" >&2
  exit 1
fi

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUTPUT_DIR=${2:-"$REPO_ROOT/_build/bench/upload-$(date +%Y%m%d-%H%M%S)"}
SERVER_HOST=${SERVER_HOST:-127.0.0.1}
SERVER_PORT=${SERVER_PORT:-4433}
SERVER_URL=${SERVER_URL:-"https://$SERVER_HOST:$SERVER_PORT/upload"}
SERVER_BIN=${SERVER_BIN:-"$REPO_ROOT/_build/default/examples/eio/eio_h3_echo_server.exe"}
UPLOAD_OUT=${UPLOAD_OUT:-}
mkdir -p "$OUTPUT_DIR"

SERVER_LOG="$OUTPUT_DIR/server.log"
CURL_STDOUT="$OUTPUT_DIR/curl.stdout"
CURL_STDERR="$OUTPUT_DIR/curl.stderr"
SAMPLE_STDERR="$OUTPUT_DIR/sample.stderr"
SAMPLE_TXT="$OUTPUT_DIR/server.sample.txt"
SUMMARY_TXT="$OUTPUT_DIR/summary.txt"

cleanup() {
  if [[ -n "${SAMPLE_PID:-}" ]]; then
    wait "$SAMPLE_PID" 2>/dev/null || true
  fi
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

cd "$REPO_ROOT"
if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  dune build --profile=release examples/eio/eio_h3_echo_server.exe
fi

SERVER_ARGS=( -p "$SERVER_PORT" )
if [[ -n "$UPLOAD_OUT" ]]; then
  SERVER_ARGS+=( -upload-out "$UPLOAD_OUT" )
fi

"$SERVER_BIN" "${SERVER_ARGS[@]}" > /dev/null 2>"$SERVER_LOG" &
SERVER_PID=$!

for _ in $(seq 1 50); do
  if lsof -nP -iUDP:"$SERVER_PORT" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

if [[ "${CAPTURE_SAMPLE:-1}" != "0" ]] && command -v sample >/dev/null 2>&1; then
  sample "$SERVER_PID" 15 -file "$SAMPLE_TXT" > /dev/null 2>"$SAMPLE_STDERR" &
  SAMPLE_PID=$!
fi

FILE_SHA256=$(shasum -a 256 "$FILE_PATH" | awk '{print $1}')
FILE_SIZE=$(wc -c < "$FILE_PATH" | tr -d '[:space:]')

CURL_CA_BUNDLE='' \
curl --http3-only -k -X POST \
  --data-binary @"$FILE_PATH" \
  -w 'http=%{http_version} uploaded=%{size_upload} speed=%{speed_upload}B/s total=%{time_total}s\n' \
  "$SERVER_URL" \
  >"$CURL_STDOUT" \
  2>"$CURL_STDERR"

if [[ -n "${SAMPLE_PID:-}" ]]; then
  wait "$SAMPLE_PID" || true
fi

{
  echo "file=$FILE_PATH"
  echo "size_bytes=$FILE_SIZE"
  echo "sha256=$FILE_SHA256"
  echo "server_pid=$SERVER_PID"
  echo "server_url=$SERVER_URL"
  echo
  echo "curl_result=$(tail -n 1 "$CURL_STDOUT")"
  echo
  echo "artifacts:"
  echo "  server_log=$SERVER_LOG"
  echo "  curl_stdout=$CURL_STDOUT"
  echo "  curl_stderr=$CURL_STDERR"
  if [[ -f "$SAMPLE_TXT" ]]; then
    echo "  sample_txt=$SAMPLE_TXT"
    echo "  sample_stderr=$SAMPLE_STDERR"
    echo
    echo "sample_hotspots:"
    grep -E 'camlQuic__|camlBigstringaf\$|bigstringaf_blit_to_bytes|poll  \(in libsystem_kernel' "$SAMPLE_TXT" \
      | sed -n '1,40p' || true
  fi
} >"$SUMMARY_TXT"

cat "$SUMMARY_TXT"
