#!/usr/bin/env bash

set -Eeuo pipefail

CHAPTER6_ROOT="${CHAPTER6_ROOT:-/root/BFR_Policy_Update_RS_DNN_ENGINEERING}"
CLIENT_ROOT="${CLIENT_ROOT:-/root/go/src/github.com/hyperledger/fabric/scripts/fabric-samples/test-network/DuoLayer-client}"
PYTHON_ENV="${PYTHON_ENV:-/usr/anaconda3/envs/pytorch_gpu/bin/python}"
GO_BIN="${GO_BIN:-/usr/local/go/bin/go}"
EXPORT_ROOT="$CHAPTER6_ROOT/deployment/rs_detector"
STAGE_ROOT="$CLIENT_ROOT/ipfs-data/cmd/rs_detector"

if [ ! -x "$PYTHON_ENV" ]; then
  echo "ERROR: Python environment not found: $PYTHON_ENV" >&2
  exit 1
fi
if [ ! -x "$GO_BIN" ]; then
  echo "ERROR: Go compiler not found: $GO_BIN" >&2
  exit 1
fi

"$PYTHON_ENV" "$CHAPTER6_ROOT/scripts/export_rs_detector.py" \
  --output-dir "$EXPORT_ROOT" \
  --checkpoint-index 0 \
  --sample-index 0

mkdir -p "$CLIENT_ROOT/ipfs-data/cmd"
mkdir -p "$STAGE_ROOT"
cp -a "$EXPORT_ROOT/." "$STAGE_ROOT/"

(
  cd "$CLIENT_ROOT/ipfs-data/bfrDetect"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    "$GO_BIN" build -trimpath -ldflags '-s -w' \
    -o "$CLIENT_ROOT/ipfs-data/cmd/bfrDetect" .
)
chmod +x "$CLIENT_ROOT/ipfs-data/cmd/bfrDetect"

echo "================ DETECTOR_STAGE_BEGIN ================"
echo "EXPORT_ROOT=$EXPORT_ROOT"
echo "STAGE_ROOT=$STAGE_ROOT"
echo "BINARY=$CLIENT_ROOT/ipfs-data/cmd/bfrDetect"
echo "NOTE=run this script after test_ipfs_cluster.sh because make clean removes ipfs-data/cmd"
echo "================= DETECTOR_STAGE_END ================="
