#!/usr/bin/env bash

set -Eeuo pipefail

CONTAINER="${CONTAINER:-ipfs-Alice}"
REQUESTER="${REQUESTER:-ipfs-Eve}"
CMD_DIR="${CMD_DIR:-/opt/gopath/src/github.com/hyperledger/fabric/peer/zk-Guard-client/ipfs-data/cmd}"
PROOF_DIR="$CMD_DIR/proof_exchange"

if ! docker inspect "$CONTAINER" >/dev/null 2>&1; then
  echo "ERROR: Provider container is not running: $CONTAINER" >&2
  exit 1
fi
if ! docker inspect "$REQUESTER" >/dev/null 2>&1; then
  echo "ERROR: requester container is not running: $REQUESTER" >&2
  exit 1
fi

# test_ipfs_cluster.sh performs a policy update after its retrieval check.
# Generate a fresh proof for the newest registered RootCID so that this smoke
# test never reuses a proof tied to the preceding policy version.
state_path=$(docker exec "$CONTAINER" sh -lc \
  "ls -1t '$CMD_DIR'/polylock_state/objects/state_ipfs-Alice_*.json 2>/dev/null | head -n 1")
if [ -z "$state_path" ]; then
  echo "ERROR: no registered object state found; run test_ipfs_cluster.sh first" >&2
  exit 1
fi
state_name=$(basename "$state_path")
rcid=${state_name#state_ipfs-Alice_}
rcid=${rcid%.json}
pid=$(docker exec "$REQUESTER" ipfs id -f='<id>')
if [ -z "$rcid" ] || [ -z "$pid" ]; then
  echo "ERROR: failed to resolve current RootCID or requester PeerID" >&2
  exit 1
fi

docker exec -w "$CMD_DIR" "$REQUESTER" \
  "$CMD_DIR/dataRetrieve" prove "$rcid" "$pid" "$REQUESTER" >/dev/null

proof_path=$(docker exec "$CONTAINER" sh -lc \
  "ls -1t '$PROOF_DIR'/proof_*.json 2>/dev/null | head -n 1")
if [ -z "$proof_path" ]; then
  echo "ERROR: no proof bundle found; run test_ipfs_cluster.sh first" >&2
  exit 1
fi

filename=$(basename "$proof_path")
identity=${filename#proof_}
identity=${identity%.json}
proof_rcid=${identity%%_*}
proof_pid=${identity#*_}
if [ "$proof_rcid" != "$rcid" ] || [ "$proof_pid" != "$pid" ]; then
  echo "ERROR: cannot derive RootCID and PeerID from $filename" >&2
  exit 1
fi

echo "================ DECISION_SMOKE_BEGIN ================"
echo "CONTAINER=$CONTAINER"
echo "ROOT_CID=$rcid"
echo "REQUESTER_PID=$pid"
echo "PROOF_BUNDLE=$proof_path"
docker exec -w "$CMD_DIR" "$CONTAINER" \
  "$CMD_DIR/dataRetrieve" verify "$rcid" "$pid" "$proof_path"
echo "================= DECISION_SMOKE_END ================="
