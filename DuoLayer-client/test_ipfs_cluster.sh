#!/usr/bin/env bash

set -Eeuo pipefail

# ============================================================
# Clean system-level end-to-end experiment.
#
# The Fabric network must have been rebuilt with the same AttrNum, legal
# profile-space size and sigma before this script is invoked.  Chapter-level
# sweep scripts do that automatically for every observation.
#
# Usage:
#   ./test_ipfs_cluster.sh \
#     --attr-num 100 \
#     --legal-space-size 1000 \
#     --target-sigma 0.90 \
#     --affected-users 10 \
#     --data-object-file /path/to/complete-geospatial-asset.tif
#
# Backward compatibility: one positional integer is still interpreted as
# AffectedUsers, as in the former ./test_ipfs_cluster.sh 10 interface.
# ============================================================

ATTR_NUM="${ATTR_NUM:-100}"
LEGAL_SPACE_SIZE="${LEGAL_SPACE_SIZE:-}"
TARGET_SIGMA="${TARGET_SIGMA:-0.90}"
AFFECTED_USERS="${AFFECTED_USERS:-100}"
DATA_OBJECT_BYTES="${DATA_OBJECT_BYTES:-1}"
DATA_OBJECT_FILE="${DATA_OBJECT_FILE:-}"
# Chapter 6 decision benchmark helpers.  These are opt-in and leave the
# ordinary Chapter 5 end-to-end experiment unchanged.
PREPARE_ACCESS_ONLY="${PREPARE_ACCESS_ONLY:-0}"
CAPTURE_MTP_PATH="${CAPTURE_MTP_PATH:-}"

usage() {
  sed -n '5,22p' "$0" | sed 's/^# \{0,1\}//'
}

if [ "$#" -eq 1 ] && [[ "$1" =~ ^[1-9][0-9]*$ ]]; then
  AFFECTED_USERS="$1"
  shift
fi

while [ "$#" -gt 0 ]; do
  case "$1" in
    --attr-num)
      ATTR_NUM="${2:?missing value after --attr-num}"
      shift 2
      ;;
    --legal-space-size)
      LEGAL_SPACE_SIZE="${2:?missing value after --legal-space-size}"
      shift 2
      ;;
    --target-sigma)
      TARGET_SIGMA="${2:?missing value after --target-sigma}"
      shift 2
      ;;
    --affected-users)
      AFFECTED_USERS="${2:?missing value after --affected-users}"
      shift 2
      ;;
    --data-object-bytes)
      DATA_OBJECT_BYTES="${2:?missing value after --data-object-bytes}"
      shift 2
      ;;
    --data-object-file)
      DATA_OBJECT_FILE="${2:?missing value after --data-object-file}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [ -z "$LEGAL_SPACE_SIZE" ]; then
  LEGAL_SPACE_SIZE=$((ATTR_NUM * 10))
fi

if [ -n "$DATA_OBJECT_FILE" ]; then
  if [ ! -f "$DATA_OBJECT_FILE" ] || [ ! -r "$DATA_OBJECT_FILE" ]; then
    echo "ERROR: DATA_OBJECT_FILE is not a readable regular file: $DATA_OBJECT_FILE" >&2
    exit 2
  fi
  DATA_OBJECT_BYTES=$(stat -c '%s' "$DATA_OBJECT_FILE")
fi

for integer_name in ATTR_NUM LEGAL_SPACE_SIZE AFFECTED_USERS DATA_OBJECT_BYTES; do
  integer_value="${!integer_name}"
  if ! [[ "$integer_value" =~ ^[1-9][0-9]*$ ]]; then
    echo "ERROR: $integer_name must be a positive integer; received $integer_value" >&2
    exit 2
  fi
done
if ! awk -v sigma="$TARGET_SIGMA" \
  'BEGIN { exit !(sigma > 0.0 && sigma <= 1.0) }'; then
  echo "ERROR: TARGET_SIGMA must be in (0,1]; received $TARGET_SIGMA" >&2
  exit 2
fi

SUMMARY_ATTR_NUM="NA"
SUMMARY_LEGAL_SPACE_SIZE="NA"
SUMMARY_TARGET_SIGMA="NA"
SUMMARY_DATA_OBJECT_BYTES="NA"
SUMMARY_DATA_OBJECT_NAME="NA"
SUMMARY_DATA_OBJECT_SHA256="NA"

SUMMARY_USER_REGISTER_ZKGUARD_MS="NA"
SUMMARY_USER_REGISTER_POLYLOCK_MS="NA"
SUMMARY_USER_REGISTER_SUPPORT_MS="NA"
SUMMARY_USER_REGISTER_TOTAL_MS="NA"

SUMMARY_STORAGE_POLICY_ENCODE_MS="NA"
SUMMARY_STORAGE_POLYLOCK_MS="NA"
SUMMARY_STORAGE_BLOCKCHAIN_MS="NA"
SUMMARY_STORAGE_TOTAL_MS="NA"

SUMMARY_RETRIEVE_PROOF_EXCHANGE_MS="NA"
SUMMARY_RETRIEVE_IPFS_GET_MS="NA"
SUMMARY_RETRIEVE_POLYLOCK_DECRYPT_MS="NA"
SUMMARY_RETRIEVE_TOTAL_MS="NA"

SUMMARY_POLICY_UPDATE_TOTAL_MS="NA"
SUMMARY_POLICY_OBSERVED_DELTA="NA"
SUMMARY_POLICY_DELTA_ADD="NA"
SUMMARY_POLICY_DELTA_RM="NA"
ATTRIBUTE_UPDATE_TOTAL_MS="NA"

HOST_CLIENT_DIR="/root/go/src/github.com/hyperledger/fabric/scripts/fabric-samples/test-network/DuoLayer-client/ipfs-data"
CMD_DIR="/opt/gopath/src/github.com/hyperledger/fabric/peer/DuoLayer-client/ipfs-data/cmd"

ALICE="ipfs-Alice"
EVE="ipfs-Eve"
NODES=("$ALICE" "$EVE")

GET_TIMEOUT="${GET_TIMEOUT:-180}"
TEST_OBJECT_PATH="/root/object.txt"

# ============================================================
# Build the parameter-dependent client binaries
# ============================================================

cd "$HOST_CLIENT_DIR"
make clean >/dev/null
make all >/dev/null

for bin in systemInit dataStorage dataRetrieve dataDecrypt policyUpdate attributeUpdate; do
  if [ ! -x "./cmd/$bin" ]; then
    echo "ERROR: required binary is missing: cmd/$bin" >&2
    exit 1
  fi
done

cp -a /root/acIPFS/XAuth/go-ipfs/cmd/ipfs/ipfs "$HOST_CLIENT_DIR/cmd/"

# Stage a complete real-world geospatial asset into the bind-mounted command
# directory after `make clean`, which deliberately removes previous contents.
if [ -n "$DATA_OBJECT_FILE" ]; then
  DATA_OBJECT_NAME=$(basename "$DATA_OBJECT_FILE")
  DATA_OBJECT_SHA256=$(sha256sum "$DATA_OBJECT_FILE" | awk '{print $1}')
  STAGED_OBJECT_DIR_HOST="$HOST_CLIENT_DIR/cmd/experiment_data"
  STAGED_OBJECT_PATH_HOST="$STAGED_OBJECT_DIR_HOST/$DATA_OBJECT_NAME"
  mkdir -p "$STAGED_OBJECT_DIR_HOST"
  cp -a "$DATA_OBJECT_FILE" "$STAGED_OBJECT_PATH_HOST"
  TEST_OBJECT_PATH="$CMD_DIR/experiment_data/$DATA_OBJECT_NAME"
else
  DATA_OBJECT_NAME="generated_zero_payload.bin"
  DATA_OBJECT_SHA256="NA"
fi

# ============================================================
# Minimal IPFS preparation
# ============================================================

reset_ipfs_node () {
  local node="$1"

  docker exec "$node" sh -lc '
    set +e
    pkill -TERM -f "[i]pfs daemon" >/dev/null 2>&1 || true
    sleep 2
    pkill -KILL -f "[i]pfs daemon" >/dev/null 2>&1 || true
    sleep 1
    rm -rf /root/.ipfs
    rm -f /root/ipfs.log /root/*.log
    rm -f /usr/local/bin/ipfs /usr/bin/ipfs
  ' >/dev/null 2>&1 || true

  docker exec "$node" cp -a "$CMD_DIR/ipfs" /usr/bin/ipfs
  docker exec "$node" chmod +x /usr/bin/ipfs
  docker exec "$node" ipfs init >/dev/null 2>&1
  docker exec "$node" ipfs bootstrap rm all >/dev/null 2>&1 || true
  if [ "$node" = "$ALICE" ] && [ -n "$CAPTURE_MTP_PATH" ]; then
    docker exec -e ZKGUARD_CAPTURE_PROOF="$CAPTURE_MTP_PATH" \
      "$node" sh -lc "nohup ipfs daemon > /root/ipfs.log 2>&1 &"
  else
    docker exec "$node" sh -lc "nohup ipfs daemon > /root/ipfs.log 2>&1 &"
  fi

  local attempt
  for attempt in $(seq 1 30); do
    if docker exec "$node" sh -lc "timeout 3 ipfs id >/dev/null 2>&1"; then
      return 0
    fi
    sleep 1
  done

  echo "ERROR: IPFS daemon did not become ready on $node" >&2
  docker exec "$node" sh -lc "tail -n 120 /root/ipfs.log || true" >&2
  return 1
}

peer_id_of () {
  docker exec "$1" ipfs id -f='<id>\n' 2>/dev/null |
    tr -d '\r' |
    tr -d '\n'
}

connect_ipfs_nodes () {
  local src
  local dst
  local dst_id
  local dst_ip

  for src in "${NODES[@]}"; do
    for dst in "${NODES[@]}"; do
      if [ "$src" = "$dst" ]; then
        continue
      fi

      dst_id=$(peer_id_of "$dst")
      dst_ip=$(docker inspect -f \
        '{{range .NetworkSettings.Networks}}{{println .IPAddress}}{{end}}' \
        "$dst" | head -n 1 | tr -d '\r')

      if [ -z "$dst_id" ] || [ -z "$dst_ip" ]; then
        echo "ERROR: failed to resolve IPFS address for $dst" >&2
        return 1
      fi

      docker exec "$src" ipfs swarm connect \
        "/ip4/$dst_ip/tcp/4001/p2p/$dst_id" >/dev/null 2>&1
    done
  done
}

dump_ipfs_debug () {
  local cid="$1"
  local node

  echo "IPFS retrieval failed for CID=$cid" >&2
  for node in "$ALICE" "$EVE"; do
    echo "---- $node swarm peers ----" >&2
    docker exec "$node" sh -lc "ipfs swarm peers || true" >&2
    echo "---- $node ipfs ls $cid ----" >&2
    docker exec "$node" sh -lc "timeout 20 ipfs ls '$cid' || true" >&2
    echo "---- $node daemon log ----" >&2
    docker exec "$node" sh -lc "tail -n 120 /root/ipfs.log || true" >&2
  done
}

ipfs_get_or_fail () {
  local node="$1"
  local cid="$2"
  local output_path="$3"
  local timeout_sec="${4:-$GET_TIMEOUT}"

  if ! docker exec "$node" sh -lc \
    "timeout '$timeout_sec' ipfs get '$cid' -o '$output_path' >/dev/null 2>&1"; then
    dump_ipfs_debug "$cid"
    return 1
  fi
}

# ============================================================
# Parsing helpers
# ============================================================

parse_cid_from_storage () {
  echo "$1" | awk '/RootCID/ {print $NF}' | tail -n 1 | tr -d '\r'
}

parse_cid_fallback () {
  echo "$1" |
    grep -Eo 'Qm[1-9A-HJ-NP-Za-km-z]{44}|bafy[0-9a-z]+' |
    tail -n 1 |
    tr -d '\r' || true
}

parse_ms_field () {
  local text="$1"
  local key="$2"

  echo "$text" | awk -v k="$key" '
    $0 ~ "^[[:space:]]*" k "[[:space:]]*:" {
      gsub(/.*: */, "");
      gsub(/ ms.*/, "");
      gsub(/^ +/, "");
      gsub(/ +$/, "");
      print;
      exit;
    }
  ' | tr -d '\r'
}

parse_eq_field () {
  local text="$1"
  local key="$2"

  echo "$text" | awk -F= -v k="$key" '
    $1 == k {
      gsub(/^ +/, "", $2);
      gsub(/ +$/, "", $2);
      print $2;
      exit;
    }
  ' | tr -d '\r' | tr -d '\n'
}

parse_metric_ms () {
  local text="$1"
  local key="$2"
  local value

  value=$(parse_eq_field "$text" "$key")
  if [ -z "$value" ]; then
    value=$(parse_eq_field "$text" "${key}_MS")
  fi
  if [ -z "$value" ]; then
    value=$(parse_ms_field "$text" "$key")
  fi
  echo "$value" | tr -d '\r' | tr -d '\n'
}

sum_ms_values () {
  awk -v a="$1" -v b="$2" -v c="${3:-0}" 'BEGIN {
    if (a == "" || b == "" || c == "" || a == "NA" || b == "NA" || c == "NA") {
      print "NA";
      exit;
    }
    printf "%.3f", a+b+c;
  }'
}

subtract_ms_values () {
  awk -v total="$1" -v a="$2" -v b="${3:-0}" 'BEGIN {
    if (total == "" || a == "" || b == "" || total == "NA" || a == "NA" || b == "NA") {
      print "NA";
      exit;
    }
    value = total-a-b;
    if (value < 0) value = 0;
    printf "%.3f", value;
  }'
}

now_ms () {
  date +%s%3N
}

parse_proof_bundle_path () {
  local text="$1"

  echo "$text" | awk -F= '
    $1 == "PROOF_BUNDLE_PATH" {
      gsub(/^ +/, "", $2);
      gsub(/ +$/, "", $2);
      print $2;
      exit;
    }
  ' | tr -d '\r' | tr -d '\n'
}

# ============================================================
# Core experiment helpers
# ============================================================

make_proof_for_request () {
  local cid="$1"
  local requester="$2"
  local requester_pid="$3"
  local prove_out
  local proof_path

  # CMD_DIR is the same bind-mounted directory in requester and provider.
  # The requester writes the proof bundle once; the provider reads it directly.
  prove_out=$(docker exec -w "$CMD_DIR" "$requester" \
    "$CMD_DIR/dataRetrieve" prove "$cid" "$requester_pid" "$requester")

  proof_path=$(parse_proof_bundle_path "$prove_out")
  if [ -z "$proof_path" ]; then
    echo "ERROR: failed to parse proof bundle path" >&2
    return 1
  fi
}

check_hash_equal () {
  local decrypted_file="$1"
  local reference_file="$2"
  local decrypted_hash
  local reference_hash

  decrypted_hash=$(docker exec "$EVE" sh -lc \
    "sha256sum '$decrypted_file' | awk '{print \$1}'")
  reference_hash=$(docker exec "$EVE" sh -lc \
    "sha256sum '$reference_file' | awk '{print \$1}'")

  if [ "$decrypted_hash" != "$reference_hash" ]; then
    echo "ERROR: decrypted plaintext hash mismatch" >&2
    return 1
  fi
}

require_summary_value () {
  local name="$1"
  local value="${!name:-}"

  if [ -z "$value" ] || [ "$value" = "NA" ]; then
    echo "ERROR: missing system-comparison metric $name" >&2
    return 1
  fi
}

require_expected_configuration () {
  if [ "$SUMMARY_ATTR_NUM" -ne "$ATTR_NUM" ]; then
    echo "ERROR: deployed AttrNum=$SUMMARY_ATTR_NUM, requested ATTR_NUM=$ATTR_NUM; rebuild Fabric for this case" >&2
    return 1
  fi
  if [ "$SUMMARY_LEGAL_SPACE_SIZE" -ne "$LEGAL_SPACE_SIZE" ]; then
    echo "ERROR: deployed legal space=$SUMMARY_LEGAL_SPACE_SIZE, requested LEGAL_SPACE_SIZE=$LEGAL_SPACE_SIZE" >&2
    return 1
  fi
  if ! awk -v actual="$SUMMARY_TARGET_SIGMA" -v expected="$TARGET_SIGMA" \
    'BEGIN { d=actual-expected; if (d<0) d=-d; exit !(d <= 0.000001) }'; then
    echo "ERROR: deployed sigma=$SUMMARY_TARGET_SIGMA, requested TARGET_SIGMA=$TARGET_SIGMA" >&2
    return 1
  fi
  if [ "$SUMMARY_DATA_OBJECT_BYTES" -ne "$DATA_OBJECT_BYTES" ]; then
    echo "ERROR: measured object bytes=$SUMMARY_DATA_OBJECT_BYTES, requested DATA_OBJECT_BYTES=$DATA_OBJECT_BYTES" >&2
    return 1
  fi
}

print_system_comparison_summary () {
  local required_vars
  local var_name

  required_vars="SUMMARY_ATTR_NUM SUMMARY_LEGAL_SPACE_SIZE SUMMARY_TARGET_SIGMA SUMMARY_DATA_OBJECT_BYTES SUMMARY_USER_REGISTER_ZKGUARD_MS SUMMARY_USER_REGISTER_POLYLOCK_MS SUMMARY_USER_REGISTER_SUPPORT_MS SUMMARY_USER_REGISTER_TOTAL_MS SUMMARY_STORAGE_POLICY_ENCODE_MS SUMMARY_STORAGE_POLYLOCK_MS SUMMARY_STORAGE_BLOCKCHAIN_MS SUMMARY_STORAGE_TOTAL_MS SUMMARY_RETRIEVE_PROOF_EXCHANGE_MS SUMMARY_RETRIEVE_IPFS_GET_MS SUMMARY_RETRIEVE_POLYLOCK_DECRYPT_MS SUMMARY_RETRIEVE_TOTAL_MS SUMMARY_POLICY_UPDATE_TOTAL_MS SUMMARY_POLICY_OBSERVED_DELTA SUMMARY_POLICY_DELTA_ADD SUMMARY_POLICY_DELTA_RM ATTRIBUTE_UPDATE_TOTAL_MS"

  for var_name in $required_vars; do
    require_summary_value "$var_name"
  done

  echo "================ EXPERIMENT_SUMMARY_BEGIN ================"
  echo "EXPERIMENT=SystemLevelComparison"
  echo "ATTR_NUM=$SUMMARY_ATTR_NUM"
  echo "LEGAL_SPACE_SIZE=$SUMMARY_LEGAL_SPACE_SIZE"
  echo "TARGET_SIGMA=$SUMMARY_TARGET_SIGMA"
  echo "AFFECTED_USERS=$AFFECTED_USERS"
  echo "DATA_OBJECT_BYTES=$SUMMARY_DATA_OBJECT_BYTES"
  echo "DATA_OBJECT_NAME=$SUMMARY_DATA_OBJECT_NAME"
  echo "DATA_OBJECT_SHA256=$SUMMARY_DATA_OBJECT_SHA256"
  echo "USER_REGISTER_ZKGUARD_MS=$SUMMARY_USER_REGISTER_ZKGUARD_MS"
  echo "USER_REGISTER_POLYLOCK_KEYGEN_MS=$SUMMARY_USER_REGISTER_POLYLOCK_MS"
  echo "USER_REGISTER_SUPPORT_MS=$SUMMARY_USER_REGISTER_SUPPORT_MS"
  echo "USER_REGISTER_TOTAL_MS=$SUMMARY_USER_REGISTER_TOTAL_MS"
  echo "DATA_STORAGE_POLICY_ENCODE_MS=$SUMMARY_STORAGE_POLICY_ENCODE_MS"
  echo "DATA_STORAGE_POLYLOCK_MS=$SUMMARY_STORAGE_POLYLOCK_MS"
  echo "DATA_STORAGE_BLOCKCHAIN_MS=$SUMMARY_STORAGE_BLOCKCHAIN_MS"
  echo "DATA_STORAGE_TOTAL_MS=$SUMMARY_STORAGE_TOTAL_MS"
  echo "DATA_RETRIEVE_PROOF_EXCHANGE_MS=$SUMMARY_RETRIEVE_PROOF_EXCHANGE_MS"
  echo "DATA_RETRIEVE_IPFS_GET_MS=$SUMMARY_RETRIEVE_IPFS_GET_MS"
  echo "DATA_RETRIEVE_POLYLOCK_DECRYPT_MS=$SUMMARY_RETRIEVE_POLYLOCK_DECRYPT_MS"
  echo "DATA_RETRIEVE_TOTAL_MS=$SUMMARY_RETRIEVE_TOTAL_MS"
  echo "POLICY_UPDATE_TOTAL_MS=$SUMMARY_POLICY_UPDATE_TOTAL_MS"
  echo "POLICY_UPDATE_OBSERVED_DELTA=$SUMMARY_POLICY_OBSERVED_DELTA"
  echo "POLICY_UPDATE_DELTA_ADD=$SUMMARY_POLICY_DELTA_ADD"
  echo "POLICY_UPDATE_DELTA_RM=$SUMMARY_POLICY_DELTA_RM"
  echo "ATTRIBUTE_UPDATE_TOTAL_MS=$ATTRIBUTE_UPDATE_TOTAL_MS"
  echo "================= EXPERIMENT_SUMMARY_END ================="
}

print_policy_update_summary () {
  local keys
  local key
  local value

  keys="ATTR_NUM LEGAL_SPACE_SIZE TARGET_SIGMA OLD_EFFECTIVE_ROOTS NEW_EFFECTIVE_ROOTS DELTA_ADD DELTA_RM AFFECTED_BUCKETS OLD_BUCKET_COUNT NEW_BUCKET_COUNT OBSERVED_DELTA MCONF_GZIP_BYTES LOCK_CT_BYTES MCONF_GENERATE_MS RESOLVE_ROOT_VERSIONS_MS LOCK_REFRESH_MS OBJECT_BUILD_MS IPFS_ADD_LOCK_ROOT_MS BLOCKCHAIN_REGISTER_MS POLICY_UPDATE_TOTAL_MS POLICY_UPDATE_CORE_WALL_MS POLICY_UPDATE_E2E_EXCL_POLICY_GEN_MS DATA_CID_REUSED OLD_ROOT_CID NEW_ROOT_CID"

  echo "================ EXPERIMENT_SUMMARY_BEGIN ================"
  echo "EXPERIMENT=PolicyUpdate"
  for key in $keys; do
    value=$(parse_eq_field "$UPDATE_OUT" "$key")
    if [ -z "$value" ]; then
      echo "ERROR: missing PolicyUpdate metric $key" >&2
      return 1
    fi
    echo "$key=$value"
  done
  echo "================= EXPERIMENT_SUMMARY_END ================="
}

print_attribute_update_summary () {
  local keys
  local key
  local value

  keys="LOCAL_COMMIT_REFRESH_MS CHAIN_ATTRIBUTE_UPDATE_MS POLYLOCK_KEYGEN_TOTAL_MS ATTRIBUTE_UPDATE_TOTAL_MS PROFILE_SPACE_LOAD_DIAG_MS ATTRIBUTE_UPDATE_WALL_EXCL_PROFILE_SPACE_MS ATTRIBUTE_UPDATE_WALL_MS"

  echo "================ EXPERIMENT_SUMMARY_BEGIN ================"
  echo "EXPERIMENT=AttributeUpdate"
  echo "ATTR_NUM=$ATTR_NUM"
  echo "LEGAL_SPACE_SIZE=$LEGAL_SPACE_SIZE"
  echo "TARGET_SIGMA=$TARGET_SIGMA"
  echo "AFFECTED_USERS=$AFFECTED_USERS"
  for key in $keys; do
    value=$(parse_metric_ms "$ATTR_OUT" "$key")
    if [ -z "$value" ]; then
      echo "ERROR: missing AttributeUpdate metric $key" >&2
      return 1
    fi
    echo "$key=$value"
  done
  echo "================= EXPERIMENT_SUMMARY_END ================="
}

# ============================================================
# 1. Prepare the two IPFS nodes used by the experiment
# ============================================================

for node in "${NODES[@]}"; do
  reset_ipfs_node "$node"
done
connect_ipfs_nodes

# ============================================================
# 2. System setup and representative user registration
# ============================================================

for node in "$ALICE" "$EVE"; do
  PID=$(peer_id_of "$node")
  INIT_OUT=$(docker exec -w "$CMD_DIR" "$node" \
    "$CMD_DIR/systemInit" "$node" "/root/.ipfs/config")

  if [ "$node" = "$EVE" ]; then
    SYSTEM_INIT_WALL_MS=$(parse_ms_field "$INIT_OUT" "SystemInit")
    UNIVERSAL_SETUP_MS=$(parse_ms_field "$INIT_OUT" "UniversalSetup")
    PROFILE_SPACE_MS=$(parse_ms_field "$INIT_OUT" "ProfileSpace")
    SUMMARY_USER_REGISTER_ZKGUARD_MS=$(parse_ms_field "$INIT_OUT" "UserRegister")
    SUMMARY_USER_REGISTER_POLYLOCK_MS=$(parse_ms_field "$INIT_OUT" "PolyLockKeyGen")
    SUMMARY_USER_REGISTER_TOTAL_MS=$(subtract_ms_values \
      "$SYSTEM_INIT_WALL_MS" "$UNIVERSAL_SETUP_MS" "$PROFILE_SPACE_MS")
    USER_REGISTER_CORE_SUM_MS=$(sum_ms_values \
      "$SUMMARY_USER_REGISTER_ZKGUARD_MS" "$SUMMARY_USER_REGISTER_POLYLOCK_MS")
    SUMMARY_USER_REGISTER_SUPPORT_MS=$(subtract_ms_values \
      "$SUMMARY_USER_REGISTER_TOTAL_MS" "$USER_REGISTER_CORE_SUM_MS")
  fi
done

# ============================================================
# 3. Minimal linked object and data storage
# ============================================================

if [ -n "$DATA_OBJECT_FILE" ]; then
  for node in "$ALICE" "$EVE"; do
    docker exec "$node" sh -lc \
      "test -f '$TEST_OBJECT_PATH' && test \"\$(wc -c < '$TEST_OBJECT_PATH')\" -eq '$DATA_OBJECT_BYTES' && test \"\$(sha256sum '$TEST_OBJECT_PATH' | cut -d ' ' -f1)\" = '$DATA_OBJECT_SHA256'"
  done
else
  for node in "$ALICE" "$EVE"; do
    docker exec "$node" sh -lc \
      "head -c '$DATA_OBJECT_BYTES' /dev/zero > '$TEST_OBJECT_PATH' && test \"\$(wc -c < '$TEST_OBJECT_PATH')\" -eq '$DATA_OBJECT_BYTES'"
  done
fi

SUMMARY_DATA_OBJECT_NAME="$DATA_OBJECT_NAME"
SUMMARY_DATA_OBJECT_SHA256="$DATA_OBJECT_SHA256"

APID=$(peer_id_of "$ALICE")
STORAGE_OUT=$(docker exec -w "$CMD_DIR" "$ALICE" \
  "$CMD_DIR/dataStorage" "$TEST_OBJECT_PATH" "$APID" "$ALICE")

SUMMARY_DATA_OBJECT_BYTES=$(docker exec "$ALICE" sh -lc \
  "wc -c < '$TEST_OBJECT_PATH'" | tr -d '\r' | tr -d ' ')
SUMMARY_STORAGE_POLICY_ENCODE_MS=$(parse_ms_field "$STORAGE_OUT" "encodePolicy")
SUMMARY_STORAGE_POLYLOCK_MS=$(parse_ms_field "$STORAGE_OUT" "polylockStorage")
SUMMARY_STORAGE_BLOCKCHAIN_MS=$(parse_ms_field "$STORAGE_OUT" "blockchainStorage")
SUMMARY_STORAGE_TOTAL_MS=$(sum_ms_values \
  "$SUMMARY_STORAGE_POLICY_ENCODE_MS" \
  "$SUMMARY_STORAGE_POLYLOCK_MS" \
  "$SUMMARY_STORAGE_BLOCKCHAIN_MS")

CID=$(parse_cid_from_storage "$STORAGE_OUT")
if [ -z "$CID" ]; then
  CID=$(parse_cid_fallback "$STORAGE_OUT")
fi
if [ -z "$CID" ]; then
  echo "ERROR: failed to parse RootCID from dataStorage output" >&2
  exit 1
fi

# ============================================================
# 4. End-to-end controlled data retrieval
# ============================================================

docker exec "$EVE" sh -lc "rm -rf /root/ls_obj /root/ls_retrieved.bin"

# PeerID lookup is deliberately outside the proof-exchange timer.
REQUESTER_PID=$(peer_id_of "$EVE")
if [ -z "$REQUESTER_PID" ]; then
  echo "ERROR: failed to resolve requester PeerID" >&2
  exit 1
fi

PROOF_START_MS=$(now_ms)
make_proof_for_request "$CID" "$EVE" "$REQUESTER_PID"
PROOF_END_MS=$(now_ms)

IPFS_GET_START_MS=$(now_ms)
ipfs_get_or_fail "$EVE" "$CID" "/root/ls_obj" "$GET_TIMEOUT"
IPFS_GET_END_MS=$(now_ms)

docker exec "$EVE" sh -lc \
  "test -f /root/ls_obj/data.ct && test -f /root/ls_obj/lock.ct"

DECRYPT_START_MS=$(now_ms)
docker exec -w "$CMD_DIR" "$EVE" \
  "$CMD_DIR/dataDecrypt" "/root/ls_obj" "$EVE" "/root/ls_retrieved.bin" \
  >/dev/null
DECRYPT_END_MS=$(now_ms)

SUMMARY_RETRIEVE_PROOF_EXCHANGE_MS=$((PROOF_END_MS - PROOF_START_MS))
SUMMARY_RETRIEVE_IPFS_GET_MS=$((IPFS_GET_END_MS - IPFS_GET_START_MS))
SUMMARY_RETRIEVE_POLYLOCK_DECRYPT_MS=$((DECRYPT_END_MS - DECRYPT_START_MS))
SUMMARY_RETRIEVE_TOTAL_MS=$(sum_ms_values \
  "$SUMMARY_RETRIEVE_PROOF_EXCHANGE_MS" \
  "$SUMMARY_RETRIEVE_IPFS_GET_MS" \
  "$SUMMARY_RETRIEVE_POLYLOCK_DECRYPT_MS")

check_hash_equal "/root/ls_retrieved.bin" "$TEST_OBJECT_PATH"

if [ "$PREPARE_ACCESS_ONLY" = "1" ]; then
  echo "CH06_ACCESS_STATE_READY=true"
  echo "ATTR_NUM=$ATTR_NUM"
  echo "LEGAL_SPACE_SIZE=$LEGAL_SPACE_SIZE"
  echo "ROOT_CID=$CID"
  echo "REQUESTER_PEER_ID=$REQUESTER_PID"
  echo "CAPTURE_MTP_PATH=$CAPTURE_MTP_PATH"
  exit 0
fi

# ============================================================
# 5. End-to-end double-layer policy update
# ============================================================

UPDATE_OUT=$(docker exec -w "$CMD_DIR" "$ALICE" \
  "$CMD_DIR/policyUpdate" "$CID" "$APID" "$ALICE")

SUMMARY_POLICY_UPDATE_TOTAL_MS=$(parse_eq_field "$UPDATE_OUT" "POLICY_UPDATE_TOTAL_MS")
SUMMARY_POLICY_OBSERVED_DELTA=$(parse_eq_field "$UPDATE_OUT" "OBSERVED_DELTA")
SUMMARY_POLICY_DELTA_ADD=$(parse_eq_field "$UPDATE_OUT" "DELTA_ADD")
SUMMARY_POLICY_DELTA_RM=$(parse_eq_field "$UPDATE_OUT" "DELTA_RM")
SUMMARY_ATTR_NUM=$(parse_eq_field "$UPDATE_OUT" "ATTR_NUM")
SUMMARY_LEGAL_SPACE_SIZE=$(parse_eq_field "$UPDATE_OUT" "LEGAL_SPACE_SIZE")
SUMMARY_TARGET_SIGMA=$(parse_eq_field "$UPDATE_OUT" "TARGET_SIGMA")

# ============================================================
# 6. End-to-end attribute update
# ============================================================

ATTR_OUT=$(docker exec -w "$CMD_DIR" "$EVE" \
  "$CMD_DIR/attributeUpdate" "/root/.ipfs/config" "$EVE" "$AFFECTED_USERS")
ATTRIBUTE_UPDATE_TOTAL_MS=$(parse_metric_ms "$ATTR_OUT" "ATTRIBUTE_UPDATE_TOTAL_MS")

# The successful path emits only the experiment summary required by the sweep.
require_expected_configuration
print_policy_update_summary
print_attribute_update_summary
print_system_comparison_summary
