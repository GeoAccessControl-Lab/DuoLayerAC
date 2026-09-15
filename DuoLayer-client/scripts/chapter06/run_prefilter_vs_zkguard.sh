#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
RUNS=200
WARMUP_RUNS=30
OUTPUT_DIR="$ROOT_DIR/experiments/results/chapter06/prefilter_vs_zkguard"
CONTAINER="ipfs-Alice"
REQUESTER="ipfs-Eve"
CMD_DIR="/opt/gopath/src/github.com/hyperledger/fabric/peer/DuoLayer-client/ipfs-data/cmd"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --runs) RUNS="$2"; shift 2 ;;
    --warmup-runs) WARMUP_RUNS="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --container) CONTAINER="$2"; shift 2 ;;
    --requester) REQUESTER="$2"; shift 2 ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
  esac
done

if ! [[ "$RUNS" =~ ^[1-9][0-9]*$ ]] || ! [[ "$WARMUP_RUNS" =~ ^[0-9]+$ ]]; then
  echo "ERROR: runs must be positive and warmup-runs nonnegative" >&2
  exit 2
fi
for name in "$CONTAINER" "$REQUESTER"; do
  if ! docker inspect "$name" >/dev/null 2>&1; then
    echo "ERROR: container is not running: $name" >&2
    exit 1
  fi
done

mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR"/*.csv "$OUTPUT_DIR"/*.txt

# Export the frozen RS checkpoints and build the pure-Go forward evaluator.
"$ROOT_DIR/scripts/chapter06/stage_bfr_detector.sh"

for model in LR DNN; do
  lower=$(printf '%s' "$model" | tr '[:upper:]' '[:lower:]')
  container_csv="/tmp/bfr_${lower}_raw.csv"
  docker exec "$CONTAINER" rm -f "$container_csv"
  docker exec -w "$CMD_DIR" "$CONTAINER" \
    "$CMD_DIR/bfrDetect" \
    --model-root "$CMD_DIR/rs_detector" \
    --model "$model" \
    --warmup-runs "$WARMUP_RUNS" \
    --runs "$RUNS" \
    --csv "$container_csv" \
    > "$OUTPUT_DIR/bfr_${lower}_summary.txt"
  docker cp "$CONTAINER:$container_csv" "$OUTPUT_DIR/bfr_${lower}_raw.csv" >/dev/null
done

# Produce a user proof for the current object/policy version once. The formal
# zk-Guard measurement is taken inside the Provider, from receipt of the first
# protected block request (before MTP verification) to the returned chain
# decision. It therefore includes MTP verification and the complete provider-
# to-chain authorization path, but excludes user-side proof generation.
state_path=$(docker exec "$CONTAINER" sh -lc \
  "ls -1t '$CMD_DIR'/polylock_state/objects/state_ipfs-Alice_*.json 2>/dev/null | head -n 1")
if [ -z "$state_path" ]; then
  echo "ERROR: no current object state; run test_ipfs_cluster.sh first" >&2
  exit 1
fi
state_name=$(basename "$state_path")
rcid=${state_name#state_ipfs-Alice_}
rcid=${rcid%.json}
pid=$(docker exec "$REQUESTER" ipfs id -f='<id>')
docker exec -w "$CMD_DIR" "$REQUESTER" \
  "$CMD_DIR/dataRetrieve" prove "$rcid" "$pid" "$REQUESTER" >/dev/null
proof_path=$(docker exec "$CONTAINER" sh -lc \
  "ls -1t '$CMD_DIR'/proof_exchange/proof_${rcid}_${pid}.json 2>/dev/null | head -n 1")
if [ -z "$proof_path" ]; then
  echo "ERROR: current proof bundle was not generated" >&2
  exit 1
fi

stop_daemon() {
  docker exec "$1" sh -lc 'pkill -f "[i]pfs daemon" >/dev/null 2>&1 || true' >/dev/null 2>&1 || true
}

wait_daemon() {
  local node="$1"
  for _ in $(seq 1 120); do
    if docker exec "$node" ipfs id >/dev/null 2>&1; then return 0; fi
    sleep 0.25
  done
  echo "ERROR: IPFS daemon did not become ready: $node" >&2
  exit 1
}

start_daemon() {
  local node="$1" trace="$2"
  docker exec -d \
    -e ZKGUARD_MTP_MODE=zkguard \
    -e ZKGUARD_MTP_METRICS=0 \
    -e ZKGUARD_AC_TRACE="$trace" \
    "$node" ipfs daemon >/dev/null
  wait_daemon "$node"
}

connect_pair() {
  local address
  address=$(docker exec "$CONTAINER" ipfs id | jq -r '.Addresses[] | select(contains("/ip4/172.") or contains("/ip4/192.") or contains("/ip4/10."))' | head -n1)
  docker exec "$REQUESTER" ipfs swarm connect "$address" >/dev/null 2>&1 || true
}

# Restart the requester once in zk-Guard mode so its modified DAG traversal
# attaches MTP evidence. The Provider is restarted for every observation to
# clear its authorized-root cache and force one complete decision.
stop_daemon "$REQUESTER"
start_daemon "$REQUESTER" 0

raw="$OUTPUT_DIR/zkguard_raw.csv"
printf '%s\n' 'iteration,provider_permission_decision_ms,proof_bundle_read_ms,chain_decision_ms,verify_total_ms,chaincode_verify_ms' > "$raw"

measure_once() {
  local iteration="$1" record="$2"
  stop_daemon "$CONTAINER"
  docker exec "$CONTAINER" rm -f /root/ac_mtp_trace.log
  start_daemon "$CONTAINER" 1
  connect_pair
  docker exec "$REQUESTER" rm -rf /root/ch06_permission_probe
  docker exec "$REQUESTER" ipfs repo gc >/dev/null 2>&1 || true
  timeout 180 docker exec "$REQUESTER" ipfs get "$rcid" -o /root/ch06_permission_probe >/dev/null 2>&1
  docker cp "$CONTAINER:/root/ac_mtp_trace.log" "$OUTPUT_DIR/ac_mtp_trace_current.log" >/dev/null
  values=$(python3 "$ROOT_DIR/scripts/chapter06/extract_permission_timing.py" \
    --trace "$OUTPUT_DIR/ac_mtp_trace_current.log")
  if [ "$record" = 1 ]; then
    printf '%d,%s\n' "$iteration" "$values" >> "$raw"
  fi
}

for ((index=1; index<=WARMUP_RUNS; index++)); do
  measure_once "$index" 0
done
for ((index=1; index<=RUNS; index++)); do
  measure_once "$index" 1
done
rm -f "$OUTPUT_DIR/ac_mtp_trace_current.log"

python3 "$ROOT_DIR/scripts/chapter06/summarize_prefilter_vs_zkguard.py" \
  --input-dir "$OUTPUT_DIR" \
  --output-dir "$OUTPUT_DIR"

printf '\nFormal experiment completed.\n'
printf 'Raw and summary CSV files: %s\n' "$OUTPUT_DIR"
