#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/bench_h3_upload_series.sh /path/to/file [output-dir]

Runs scripts/bench_h3_upload.sh multiple times and prints a short aggregate
summary with median/min/max totals and speeds.

Environment:
  RUNS=3         Number of runs
  SKIP_BUILD=1   Skip rebuilding the server binary on each run
  CAPTURE_SAMPLE=0  Disable the macOS sampler during throughput runs
EOF
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 1
fi

FILE_PATH=$1
OUTPUT_DIR=${2:-"$(pwd)/_build/bench/upload-series-$(date +%Y%m%d-%H%M%S)"}
RUNS=${RUNS:-3}

if [[ ! -f "$FILE_PATH" ]]; then
  echo "input file not found: $FILE_PATH" >&2
  exit 1
fi

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$OUTPUT_DIR"

cd "$REPO_ROOT"

for i in $(seq 1 "$RUNS"); do
  run_dir="$OUTPUT_DIR/run-$i"
  echo "==> run $i/$RUNS: $run_dir"
  scripts/bench_h3_upload.sh "$FILE_PATH" "$run_dir"
done

ruby - "$OUTPUT_DIR" "$RUNS" <<'RUBY'
require 'pathname'

output_dir = Pathname(ARGV[0])
runs = Integer(ARGV[1])

entries =
  (1..runs).map do |i|
    curl_stdout = (output_dir / "run-#{i}" / "curl.stdout").read.strip
    md = curl_stdout.match(/speed=(\d+)B\/s total=([0-9.]+)s/)
    raise "could not parse curl result for run #{i}: #{curl_stdout.inspect}" unless md
    { run: i, speed: Integer(md[1]), total: Float(md[2]), line: curl_stdout }
  end

totals = entries.map { |e| e[:total] }.sort
speeds = entries.map { |e| e[:speed] }.sort

def median(values)
  n = values.length
  if n.odd?
    values[n / 2]
  else
    (values[n / 2 - 1] + values[n / 2]) / 2.0
  end
end

summary = output_dir / "summary.txt"

File.open(summary, "w") do |io|
  io.puts "runs=#{runs}"
  entries.each do |entry|
    io.puts "run#{entry[:run]}=#{entry[:line]}"
  end
  io.puts
  io.puts format("median_total=%.6fs", median(totals))
  io.puts format("min_total=%.6fs", totals.first)
  io.puts format("max_total=%.6fs", totals.last)
  io.puts format("median_speed=%dB/s", median(speeds).round)
  io.puts format("min_speed=%dB/s", speeds.first)
  io.puts format("max_speed=%dB/s", speeds.last)
end

puts File.read(summary)
RUBY
