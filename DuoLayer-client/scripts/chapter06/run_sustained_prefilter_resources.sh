#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TRIALS=5
REQUESTS=1000
WARMUP_RUNS=100
RATE=20
BASELINE_SECONDS=5
METHODS=all
OUTPUT_DIR="$ROOT_DIR/experiments/results/chapter06/sustained_prefilter_resources"
CONTAINER=ipfs-Alice
CMD_DIR=/opt/gopath/src/github.com/hyperledger/fabric/peer/DuoLayer-client/ipfs-data/cmd

while [ "$#" -gt 0 ]; do
  case "$1" in
    --trials) TRIALS="$2"; shift 2 ;;
    --requests) REQUESTS="$2"; shift 2 ;;
    --warmup-runs) WARMUP_RUNS="$2"; shift 2 ;;
    --rate) RATE="$2"; shift 2 ;;
    --baseline-seconds) BASELINE_SECONDS="$2"; shift 2 ;;
    --methods) METHODS="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
  esac
done

for value in "$TRIALS" "$REQUESTS" "$WARMUP_RUNS"; do
  [[ "$value" =~ ^[0-9]+$ ]] || { echo "ERROR: integer arguments required" >&2; exit 2; }
done
[ "$TRIALS" -gt 0 ] && [ "$REQUESTS" -gt 0 ] || { echo "ERROR: trials and requests must be positive" >&2; exit 2; }
case "$METHODS" in
  all|zkguard) ;;
  *) echo "ERROR: --methods must be all or zkguard" >&2; exit 2 ;;
esac

mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR"/*
if [ "$METHODS" = all ]; then
  "$ROOT_DIR/scripts/chapter06/stage_bfr_detector.sh" > "$OUTPUT_DIR/detector_stage.txt"
fi

proof_host="$ROOT_DIR/ipfs-data/cmd/ch06_resource_mtp.gob"
meta_host="$proof_host.meta"
bench_host="$ROOT_DIR/ipfs-data/cmd/zkguardResourceBench"
for path in "$proof_host" "$meta_host" "$bench_host"; do
  [ -s "$path" ] || { echo "ERROR: missing benchmark input: $path" >&2; exit 1; }
done
peer=$(sed -n 's/^peer=//p' "$meta_host")
leaf=$(sed -n 's/^leaf=//p' "$meta_host")
[ -n "$peer" ] && [ -n "$leaf" ] || { echo "ERROR: invalid proof metadata" >&2; exit 1; }

chaincode=$(docker ps --format '{{.Names}}' | grep '^dev-peer0.org1.example.com-acmc' | head -n1)
[ -n "$chaincode" ] || { echo "ERROR: org1 chaincode container is not running" >&2; exit 1; }

run_method() {
  local prefix="$1" model="$2" trial="$3"
  local ready="/tmp/ch06_${prefix}_${trial}.ready"
  local start="/tmp/ch06_${prefix}_${trial}.start"
  local container_csv="/tmp/ch06_${prefix}_${trial}.csv"
  local output="$OUTPUT_DIR/${prefix}_trial${trial}_command.txt"
  local json="$OUTPUT_DIR/${prefix}_trial${trial}_resource.json"
  local samples="$OUTPUT_DIR/${prefix}_trial${trial}_samples.csv"
  local containers=("$CONTAINER")
  local command=()
  if [ "$prefix" = zkguard ]; then
    containers+=(peer0.org1.example.com "$chaincode")
    command=(docker exec -w "$CMD_DIR" "$CONTAINER" "$CMD_DIR/zkguardResourceBench"
      --proof "$CMD_DIR/ch06_resource_mtp.gob" --peer "$peer" --leaf "$leaf"
      --warmup-runs "$WARMUP_RUNS" --runs "$REQUESTS" --rate "$RATE"
      --ready-file "$ready" --start-file "$start" --csv "$container_csv")
  else
    command=(docker exec -w "$CMD_DIR" "$CONTAINER" "$CMD_DIR/bfrDetect"
      --model-root "$CMD_DIR/rs_detector" --model "$model"
      --warmup-runs "$WARMUP_RUNS" --runs "$REQUESTS" --rate "$RATE"
      --ready-file "$ready" --start-file "$start" --csv "$container_csv")
  fi

  python3 "$ROOT_DIR/scripts/chapter06/run_resource_trial.py" \
    --method "$prefix" --trial "$trial" --requests "$REQUESTS" --rate "$RATE" \
    --containers "${containers[@]}" --signal-container "$CONTAINER" \
    --ready-file "$ready" --start-file "$start" \
    --baseline-seconds "$BASELINE_SECONDS" --sample-interval 0.1 \
    --output-json "$json" --samples-csv "$samples" --command-output "$output" \
    -- "${command[@]}" > "$OUTPUT_DIR/${prefix}_trial${trial}_resource.txt"
  docker cp "$CONTAINER:$container_csv" "$OUTPUT_DIR/${prefix}_trial${trial}_timing.csv" >/dev/null
  docker exec "$CONTAINER" rm -f "$ready" "$start" "$container_csv"
  printf 'completed method=%s trial=%d/%d\n' "$prefix" "$trial" "$TRIALS"
}

for ((trial=1; trial<=TRIALS; trial++)); do
  if [ "$METHODS" = zkguard ]; then
    run_method zkguard '' "$trial"
    continue
  fi
  case $((trial % 3)) in
    1) run_method bfr_lr LR "$trial"; run_method bfr_dnn DNN "$trial"; run_method zkguard '' "$trial" ;;
    2) run_method bfr_dnn DNN "$trial"; run_method zkguard '' "$trial"; run_method bfr_lr LR "$trial" ;;
    0) run_method zkguard '' "$trial"; run_method bfr_lr LR "$trial"; run_method bfr_dnn DNN "$trial" ;;
  esac
done

python3 "$ROOT_DIR/scripts/chapter06/summarize_sustained_resources.py" \
  --input-dir "$OUTPUT_DIR" --output "$OUTPUT_DIR/comparison_summary.csv" \
  --requests-per-trial "$REQUESTS" | tee "$OUTPUT_DIR/summary.txt"

echo "RESULT_DIR=$OUTPUT_DIR"
