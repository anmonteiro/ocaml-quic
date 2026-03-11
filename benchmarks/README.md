# Benchmark Dashboard

This repository publishes loopback HTTP/3 benchmark history to the `gh-pages`
branch.

## Data model

The source of truth is the append-only file:

- `gh-pages/benchmarks/results.jsonl`

Each line is a JSON object for one benchmark scenario on one commit. The current
workflow records two scenarios on every push to `master`:

- `h3_upload_curl`
- `h3_download_curl`

Each record carries the fixed benchmark profile `large-1536mib`.

## How it works

1. `.github/workflows/benchmark.yml` runs on pushes to `master`.
2. It enters the Nix `release` shell and runs:
   - `scripts/bench/run_h3_loopback_benchmarks.sh`
3. That script builds a fixed-size payload, runs the local HTTP/3 echo server,
   benchmarks upload and download with `curl --http3-only`, and prints JSONL.
4. The workflow appends the new records to `gh-pages/benchmarks/results.jsonl`.
5. It copies the static dashboard assets from `benchmarks/site/` into the
   `gh-pages` branch and pushes the update.

## Payload size

The benchmark is fixed at a `1536` MiB payload for both upload and download.

The runner script creates the payload with `truncate`/`fallocate` when
available, so the large file does not require an expensive zero-fill step
before the benchmark starts.

## Dashboard

The dashboard is intentionally buildless:

- `benchmarks/site/index.html`
- `benchmarks/site/app.js`
- `benchmarks/site/style.css`

The page fetches `benchmarks/results.jsonl` directly and renders:

- a summary
- a throughput graph
- a per-commit results table
