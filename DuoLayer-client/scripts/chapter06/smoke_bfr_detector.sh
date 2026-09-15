#!/usr/bin/env bash

set -Eeuo pipefail

CONTAINER="${CONTAINER:-ipfs-Alice}"
CMD_DIR="${CMD_DIR:-/opt/gopath/src/github.com/hyperledger/fabric/peer/DuoLayer-client/ipfs-data/cmd}"
RUNS="${RUNS:-20}"
WARMUP_RUNS="${WARMUP_RUNS:-5}"

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  echo "ERROR: Provider container is not running: $CONTAINER" >&2
  exit 1
fi

for model in LR DNN; do
  docker exec -w "$CMD_DIR" "$CONTAINER" \
    "$CMD_DIR/bfrDetect" \
    --model-root "$CMD_DIR/rs_detector" \
    --model "$model" \
    --input "$CMD_DIR/rs_detector/sample_request.json" \
    --warmup-runs "$WARMUP_RUNS" \
    --runs "$RUNS"
done
