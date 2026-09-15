#!/bin/bash

set -e


# ============================================================
# Experiment parameters
# ============================================================
# Usage:
#   ./test_ipfs_cluster.sh [AffectedUsers] [PolicyBucketRatio]
# Examples:
#   ./test_ipfs_cluster.sh
#   ./test_ipfs_cluster.sh 100
#
# AffectedUsers is used by attributeUpdate.
# PolicyBucketRatio is reserved for the future bucket-refresh experiment.
#
# Large-file benchmark is kept from the original script but disabled by default
# for attribute-update sweeps. Enable it by RUN_LARGE_BENCH=1.
# ============================================================
AFFECTED_USERS="${1:-${AFFECTED_USERS:-100}}"
POLICY_BUCKET_RATIO_RESERVED="${2:-${POLICY_BUCKET_RATIO_RESERVED:-0}}"
RUN_LARGE_BENCH="${RUN_LARGE_BENCH:-0}"

SUMMARY_ATTR_NUM="NA"
SUMMARY_LEGAL_SPACE_SIZE="NA"
SUMMARY_TARGET_SIGMA="NA"
SUMMARY_DATA_OBJECT_BYTES="NA"
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
SUMMARY_POLICY_BUCKET_REFRESH_MS="NA"
SUMMARY_POLICY_OBSERVED_DELTA="NA"
SUMMARY_POLICY_DELTA_ADD="NA"
SUMMARY_POLICY_DELTA_RM="NA"
SUMMARY_LARGE_STORAGE_MS="0"
SUMMARY_LARGE_POLICY_TOTAL_MS="0"
SUMMARY_LARGE_NEW_ONLY_BYTES="0"


# ============================================================
# Unified zk-Guard + PolyLock prototype test script
#
# Current code logic:
#   1. systemInit generates zk-Guard universal parameters and the global
#      PolyLock admissible profile space S*.
#   2. dataStorage loads S*, generates a mconf-compatible policy over S*,
#      encrypts data/lock, publishes a two-link RootCID, and registers mconf.
#   3. dataRetrieve is triggered by native IPFS retrieval; it checks local
#      attributes against S*, Reg[pid], and mconf.
#   4. dataDecrypt only performs local PolyLock decapsulation/AES decryption.
#   5. policyUpdate performs one true end-to-end policy update. It does not
#      accept a configured affected ratio; it reports the observed ratio.
#   6. attributeUpdate updates Reg[pid], VerMap, and PolyLock USK, with the
#      affected user count as an experiment parameter.
# ============================================================

# ============================================================
# 0) Optional: Recompile customized IPFS with Go 1.17
# ============================================================

# echo "recompiling ipfs......"
# cd /usr/local/
# mv go go_tmp
# mv go_1.17 go
# cd /root/acIPFS/XAuth/go-ipfs/
# go clean -cache
# make build
# cd /usr/local/
# mv go go_1.17
# mv go_tmp go

# ============================================================
# 1) Compile zk-Guard client tools
# ============================================================

HOST_CLIENT_DIR="/root/go/src/github.com/hyperledger/fabric/scripts/fabric-samples/test-network/DuoLayer-client/ipfs-data"
CMD_DIR="/opt/gopath/src/github.com/hyperledger/fabric/peer/DuoLayer-client/ipfs-data/cmd"

cd "$HOST_CLIENT_DIR"
make clean
make all

for bin in systemInit dataStorage dataRetrieve dataDecrypt policyUpdate attributeUpdate; do
  if [ ! -f "./cmd/$bin" ]; then
    echo "ERROR: cmd/$bin not found. Please add $bin to Makefile and rebuild."
    exit 1
  fi
done

# Copy customized IPFS binary to mapped cmd directory.
cp -a /root/acIPFS/XAuth/go-ipfs/cmd/ipfs/ipfs "$HOST_CLIENT_DIR/cmd/"

# ============================================================
# 2) Prepare IPFS nodes
# ============================================================

nodes=("ipfs-Alice" "ipfs-Eve" "ipfs-Bob" "ipfs-Oscar" "ipfs-Dave")

ALICE="ipfs-Alice"
EVE="ipfs-Eve"
BOB="ipfs-Bob"

GET_TIMEOUT="${GET_TIMEOUT:-180}"
LARGE_TIMEOUT="${LARGE_TIMEOUT:-7200}"
LARGE_FILE="${LARGE_FILE:-/root/polylock_1gb_random.bin}"
LARGE_SIZE_BYTES="${LARGE_SIZE_BYTES:-1073741824}"
ATTR_UPDATE_USERS="${AFFECTED_USERS}"
TEST_OBJECT_PATH="/root/object.txt"

reset_ipfs_node () {
  local node="$1"

  echo "== reset IPFS node: $node =="

  docker exec "$node" sh -lc '
    set +e
    echo "[1] killing old ipfs daemon..."
    pkill -TERM -f "[i]pfs daemon" >/dev/null 2>&1 || true
    sleep 2
    pkill -KILL -f "[i]pfs daemon" >/dev/null 2>&1 || true
    sleep 1

    echo "[2] checking residual daemon..."
    pgrep -af "[i]pfs daemon" || true

    echo "[3] removing old repo, lock, logs and binaries..."
    rm -rf /root/.ipfs
    rm -f /root/.ipfs/repo.lock
    rm -f /root/ipfs.log /root/*.log
    rm -f /usr/local/bin/ipfs /usr/bin/ipfs
  ' || true

  docker exec "$node" cp -a "$CMD_DIR/ipfs" /usr/bin/ipfs
  docker exec "$node" chmod +x /usr/bin/ipfs || true

  echo "[4] ipfs init on $node..."
  docker exec "$node" ipfs init

  echo "[5] removing default bootstrap peers on $node..."
  docker exec "$node" ipfs bootstrap rm all >/dev/null 2>&1 || true

  echo "[6] starting ipfs daemon on $node..."
  docker exec "$node" sh -lc "nohup ipfs daemon > /root/ipfs.log 2>&1 &"

  echo "[7] waiting for ipfs API on $node..."
  for k in $(seq 1 30); do
    if docker exec "$node" sh -lc "timeout 3 ipfs id >/dev/null 2>&1"; then
      echo "IPFS daemon ready on $node"
      return 0
    fi
    sleep 1
  done

  echo "ERROR: IPFS daemon not ready on $node"
  echo "---- $node daemon process ----"
  docker exec "$node" sh -lc "pgrep -af '[i]pfs daemon' || true"
  echo "---- $node /root/ipfs.log ----"
  docker exec "$node" sh -lc "cat /root/ipfs.log || true"
  exit 1
}

connect_all_ipfs_nodes () {
  echo "connecting IPFS swarm peers directly......"

  for src in "${nodes[@]}"; do
    for dst in "${nodes[@]}"; do
      if [ "$src" = "$dst" ]; then
        continue
      fi

      local dst_id
      local dst_ip
      dst_id=$(docker exec "$dst" ipfs id -f='<id>\n' | tr -d '\r' | tr -d '\n')
      dst_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{println .IPAddress}}{{end}}' "$dst" | head -n 1 | tr -d '\r')

      if [ -z "$dst_id" ] || [ -z "$dst_ip" ]; then
        echo "WARN: failed to resolve IPFS address for $dst"
        continue
      fi

      echo "$src -> $dst /ip4/$dst_ip/tcp/4001/p2p/$dst_id"
      docker exec "$src" ipfs swarm connect "/ip4/$dst_ip/tcp/4001/p2p/$dst_id" >/dev/null 2>&1 || true
    done
  done

  echo "checking swarm peers......"
  for node in "${nodes[@]}"; do
    echo "== $node peers =="
    docker exec "$node" sh -lc "ipfs swarm peers | wc -l"
  done
}

peer_id_of () {
  docker exec "$1" ipfs id -f='<id>\n' 2>/dev/null | tr -d '\r' | tr -d '\n'
}

connect_eve_to_alice () {
  local alice_id
  local alice_ip

  alice_id=$(docker exec "$ALICE" ipfs id -f='<id>\n' | tr -d '\r' | tr -d '\n')
  alice_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{println .IPAddress}}{{end}}' "$ALICE" | head -n 1 | tr -d '\r')

  echo "Reconnecting Eve to Alice: /ip4/${alice_ip}/tcp/4001/p2p/${alice_id}"
  docker exec "$EVE" ipfs swarm connect "/ip4/${alice_ip}/tcp/4001/p2p/${alice_id}" >/dev/null 2>&1 || true
}

dump_ipfs_debug () {
  local cid="$1"

  echo "================ IPFS DEBUG ================"
  echo "CID=$cid"

  for node in "$ALICE" "$EVE"; do
    echo "---- $node ipfs daemon pids ----"
    docker exec "$node" sh -lc "pgrep -af '[i]pfs daemon' || true"

    echo "---- $node swarm peers ----"
    docker exec "$node" sh -lc "ipfs swarm peers || true"

    echo "---- $node ipfs ls $cid ----"
    docker exec "$node" sh -lc "timeout 20 ipfs ls $cid || true"

    echo "---- $node ipfs refs $cid ----"
    docker exec "$node" sh -lc "timeout 20 ipfs refs $cid || true"

    echo "---- $node /root/ipfs.log tail ----"
    docker exec "$node" sh -lc "tail -n 120 /root/ipfs.log || true"
  done

  echo "============================================"
}

ipfs_get_or_fail () {
  local node="$1"
  local cid="$2"
  local output_path="$3"
  local timeout_sec="${4:-$GET_TIMEOUT}"

  echo "ipfs get on $node: cid=$cid output=$output_path timeout=${timeout_sec}s"

  if ! docker exec "$node" sh -lc "timeout $timeout_sec ipfs get $cid -o $output_path"; then
    echo "ERROR: ipfs get failed or timed out on $node, cid=$cid"
    dump_ipfs_debug "$cid"
    exit 1
  fi
}

ensure_provider_and_connection () {
  local cid="$1"

  echo "== ensure provider and connection for CID=$cid =="
  docker exec "$ALICE" sh -lc "ipfs pin add -r $cid >/dev/null 2>&1 || true"
  connect_eve_to_alice

  local alice_id
  alice_id=$(peer_id_of "$ALICE")

  echo "Checking Eve -> Alice swarm connection..."
  docker exec "$EVE" sh -lc "ipfs swarm peers | grep $alice_id || true"
}

parse_cid_from_storage () {
  echo "$1" | awk '/RootCID/ {print $NF}' | tail -n1 | tr -d '\r'
}

parse_cid_fallback () {
  echo "$1" | grep -Eo 'Qm[1-9A-HJ-NP-Za-km-z]{44}|bafy[0-9a-z]+' | tail -n1 | tr -d '\r'
}

parse_new_root_cid () {
  local text="$1"
  local cid
  cid=$(echo "$text" | awk -F= '/NEW_ROOT_CID=/{print $2}' | tail -n1 | tr -d '\r' | tr -d '\n')
  if [ -z "$cid" ]; then
    cid=$(parse_cid_from_storage "$text")
  fi
  if [ -z "$cid" ]; then
    cid=$(parse_cid_fallback "$text")
  fi
  echo "$cid"
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
    v = total-a-b;
    if (v < 0) v = 0;
    printf "%.3f", v;
  }'
}

parse_value_field () {
  local text="$1"
  local key="$2"

  echo "$text" | awk -v k="$key" '
    $0 ~ k {
      gsub(/.*: */, "");
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
  local v

  v=$(parse_eq_field "$text" "$key")
  if [ -z "$v" ]; then
    v=$(parse_eq_field "$text" "${key}_MS")
  fi
  if [ -z "$v" ]; then
    v=$(parse_ms_field "$text" "$key")
  fi
  echo "$v" | tr -d '\r' | tr -d '\n'
}

calc_local_commit_ms () {
  local total="$1"
  local chain="$2"
  local keygen="$3"

  if [ -z "$total" ] || [ -z "$chain" ] || [ -z "$keygen" ] || \
     [ "$total" = "NA" ] || [ "$chain" = "NA" ] || [ "$keygen" = "NA" ]; then
    echo "NA"
    return 0
  fi

  awk -v total="$total" -v chain="$chain" -v keygen="$keygen" 'BEGIN {
    v = total - chain - keygen;
    if (v < 0) v = 0;
    printf "%.3f", v;
  }'
}

extract_go_const () {
  local file="$1"
  local key="$2"
  if [ ! -f "$file" ]; then
    echo "NA"
    return 0
  fi
  grep -E "(^|[[:space:]])${key}[[:space:]]*=" "$file" | head -n 1 | \
    sed -E "s/.*${key}[[:space:]]*=[[:space:]]*([0-9]+(\.[0-9]+)?).*/\1/" | tr -d '\r' | tr -d '\n'
}

print_system_comparison_experiment_summary () {
  local required_vars
  local var_name
  local var_value
  local missing=0

  required_vars="SUMMARY_ATTR_NUM SUMMARY_LEGAL_SPACE_SIZE SUMMARY_TARGET_SIGMA SUMMARY_DATA_OBJECT_BYTES SUMMARY_USER_REGISTER_ZKGUARD_MS SUMMARY_USER_REGISTER_POLYLOCK_MS SUMMARY_USER_REGISTER_SUPPORT_MS SUMMARY_USER_REGISTER_TOTAL_MS SUMMARY_STORAGE_POLICY_ENCODE_MS SUMMARY_STORAGE_POLYLOCK_MS SUMMARY_STORAGE_BLOCKCHAIN_MS SUMMARY_STORAGE_TOTAL_MS SUMMARY_RETRIEVE_PROOF_EXCHANGE_MS SUMMARY_RETRIEVE_IPFS_GET_MS SUMMARY_RETRIEVE_POLYLOCK_DECRYPT_MS SUMMARY_RETRIEVE_TOTAL_MS SUMMARY_POLICY_UPDATE_TOTAL_MS SUMMARY_POLICY_OBSERVED_DELTA SUMMARY_POLICY_DELTA_ADD SUMMARY_POLICY_DELTA_RM ATTRIBUTE_UPDATE_TOTAL_MS"
  for var_name in $required_vars; do
    var_value="${!var_name:-}"
    if [ -z "$var_value" ] || [ "$var_value" = "NA" ]; then
      echo "ERROR: missing system-comparison summary metric $var_name"
      missing=1
    fi
  done
  if [ "$missing" -ne 0 ]; then
    return 1
  fi

  echo "================ EXPERIMENT_SUMMARY_BEGIN ================"
  echo "EXPERIMENT=SystemLevelComparison"
  echo "ATTR_NUM=$SUMMARY_ATTR_NUM"
  echo "LEGAL_SPACE_SIZE=$SUMMARY_LEGAL_SPACE_SIZE"
  echo "TARGET_SIGMA=$SUMMARY_TARGET_SIGMA"
  echo "AFFECTED_USERS=$AFFECTED_USERS"
  echo "DATA_OBJECT_BYTES=$SUMMARY_DATA_OBJECT_BYTES"
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
  echo "ATTRIBUTE_UPDATE_TOTAL_MS=${ATTRIBUTE_UPDATE_TOTAL_MS:-NA}"
  echo "================= EXPERIMENT_SUMMARY_END ================="
}

print_policy_update_experiment_summary () {
  local update_out="$1"
  local required_keys
  local key
  local value
  local missing=0

  required_keys="ATTR_NUM LEGAL_SPACE_SIZE TARGET_SIGMA OLD_EFFECTIVE_ROOTS NEW_EFFECTIVE_ROOTS DELTA_ADD DELTA_RM AFFECTED_BUCKETS OLD_BUCKET_COUNT NEW_BUCKET_COUNT OBSERVED_DELTA MCONF_GZIP_BYTES LOCK_CT_BYTES MCONF_GENERATE_MS RESOLVE_ROOT_VERSIONS_MS LOCK_REFRESH_MS OBJECT_BUILD_MS IPFS_ADD_LOCK_ROOT_MS BLOCKCHAIN_REGISTER_MS POLICY_UPDATE_SIX_STAGE_SUM_MS POLICY_UPDATE_TOTAL_MS POLICY_UPDATE_CORE_WALL_MS POLICY_UPDATE_WALL_EXCL_POLICY_GEN_MS POLICY_UPDATE_WALL_GAP_MS POLICY_UPDATE_WALL_GAP_PCT POLICY_UPDATE_E2E_EXCL_POLICY_GEN_MS PROGRAM_WALL_MS PROGRAM_WALL_MINUS_SIX_STAGES_MS PROGRAM_WALL_MINUS_SIX_STAGES_PCT PROGRAM_BOOTSTRAP_MS STATE_PREPARE_DIAG_MS LOCAL_PERSIST_DIAG_MS POST_PROCESS_DIAG_MS CLIENT_ARTIFACT_WRITE_DIAG_MS UNATTRIBUTED_GAP_MS DATA_CID_REUSED"

  for key in $required_keys; do
    value=$(parse_eq_field "$update_out" "$key")
    if [ -z "$value" ]; then
      echo "ERROR: missing policy-update metric $key from policyUpdate output."
      missing=1
    fi
  done
  if [ "$missing" -ne 0 ]; then
    return 1
  fi

  local attr_num
  local legal_space_size
  local target_sigma
  local old_roots
  local new_roots
  local delta_add
  local delta_rm
  local affected_buckets
  local old_bucket_count
  local new_bucket_count
  local observed_delta
  local mconf_gzip_bytes
  local lock_ct_bytes
  local mconf_kb
  local lock_ct_kb
  local mconf_generate_ms
  local resolve_roots_ms
  local lock_refresh_ms
  local object_build_ms
  local ipfs_add_ms
  local blockchain_ms
  local six_stage_sum_ms
  local total_ms
  local core_wall_ms
  local update_wall_ms
  local wall_gap_ms
  local wall_gap_pct
  local update_e2e_ms
  local program_wall_ms
  local program_wall_gap_ms
  local program_wall_gap_pct
  local policy_gen_ms
  local program_bootstrap_ms
  local state_prepare_ms
  local local_persist_ms
  local post_process_ms
  local client_artifact_write_ms
  local unattributed_gap_ms
  local data_cid_reused

  attr_num=$(parse_eq_field "$update_out" "ATTR_NUM")
  legal_space_size=$(parse_eq_field "$update_out" "LEGAL_SPACE_SIZE")
  target_sigma=$(parse_eq_field "$update_out" "TARGET_SIGMA")
  old_roots=$(parse_eq_field "$update_out" "OLD_EFFECTIVE_ROOTS")
  new_roots=$(parse_eq_field "$update_out" "NEW_EFFECTIVE_ROOTS")
  delta_add=$(parse_eq_field "$update_out" "DELTA_ADD")
  delta_rm=$(parse_eq_field "$update_out" "DELTA_RM")
  affected_buckets=$(parse_eq_field "$update_out" "AFFECTED_BUCKETS")
  old_bucket_count=$(parse_eq_field "$update_out" "OLD_BUCKET_COUNT")
  new_bucket_count=$(parse_eq_field "$update_out" "NEW_BUCKET_COUNT")
  observed_delta=$(parse_eq_field "$update_out" "OBSERVED_DELTA")
  mconf_gzip_bytes=$(parse_eq_field "$update_out" "MCONF_GZIP_BYTES")
  lock_ct_bytes=$(parse_eq_field "$update_out" "LOCK_CT_BYTES")
  mconf_kb=$(awk -v b="$mconf_gzip_bytes" 'BEGIN { printf "%.3f", b/1024.0 }')
  lock_ct_kb=$(awk -v b="$lock_ct_bytes" 'BEGIN { printf "%.3f", b/1024.0 }')
  mconf_generate_ms=$(parse_eq_field "$update_out" "MCONF_GENERATE_MS")
  resolve_roots_ms=$(parse_eq_field "$update_out" "RESOLVE_ROOT_VERSIONS_MS")
  lock_refresh_ms=$(parse_eq_field "$update_out" "LOCK_REFRESH_MS")
  object_build_ms=$(parse_eq_field "$update_out" "OBJECT_BUILD_MS")
  ipfs_add_ms=$(parse_eq_field "$update_out" "IPFS_ADD_LOCK_ROOT_MS")
  blockchain_ms=$(parse_eq_field "$update_out" "BLOCKCHAIN_REGISTER_MS")
  six_stage_sum_ms=$(parse_eq_field "$update_out" "POLICY_UPDATE_SIX_STAGE_SUM_MS")
  total_ms=$(parse_eq_field "$update_out" "POLICY_UPDATE_TOTAL_MS")
  core_wall_ms=$(parse_eq_field "$update_out" "POLICY_UPDATE_CORE_WALL_MS")
  update_wall_ms=$(parse_eq_field "$update_out" "POLICY_UPDATE_WALL_EXCL_POLICY_GEN_MS")
  wall_gap_ms=$(parse_eq_field "$update_out" "POLICY_UPDATE_WALL_GAP_MS")
  wall_gap_pct=$(parse_eq_field "$update_out" "POLICY_UPDATE_WALL_GAP_PCT")
  update_e2e_ms=$(parse_eq_field "$update_out" "POLICY_UPDATE_E2E_EXCL_POLICY_GEN_MS")
  program_wall_ms=$(parse_eq_field "$update_out" "PROGRAM_WALL_MS")
  program_wall_gap_ms=$(parse_eq_field "$update_out" "PROGRAM_WALL_MINUS_SIX_STAGES_MS")
  program_wall_gap_pct=$(parse_eq_field "$update_out" "PROGRAM_WALL_MINUS_SIX_STAGES_PCT")
  policy_gen_ms=$(parse_eq_field "$update_out" "POLICY_GEN_EXCLUDED_MS")
  program_bootstrap_ms=$(parse_eq_field "$update_out" "PROGRAM_BOOTSTRAP_MS")
  state_prepare_ms=$(parse_eq_field "$update_out" "STATE_PREPARE_DIAG_MS")
  local_persist_ms=$(parse_eq_field "$update_out" "LOCAL_PERSIST_DIAG_MS")
  post_process_ms=$(parse_eq_field "$update_out" "POST_PROCESS_DIAG_MS")
  client_artifact_write_ms=$(parse_eq_field "$update_out" "CLIENT_ARTIFACT_WRITE_DIAG_MS")
  unattributed_gap_ms=$(parse_eq_field "$update_out" "UNATTRIBUTED_GAP_MS")
  data_cid_reused=$(parse_eq_field "$update_out" "DATA_CID_REUSED")

  echo "================ EXPERIMENT_SUMMARY_BEGIN ================"
  echo "EXPERIMENT=PolicyUpdate"
  echo "ATTR_NUM=$attr_num"
  echo "LEGAL_SPACE_SIZE=$legal_space_size"
  echo "TARGET_SIGMA=$target_sigma"
  echo "OLD_EFFECTIVE_ROOTS=$old_roots"
  echo "NEW_EFFECTIVE_ROOTS=$new_roots"
  echo "DELTA_ADD=$delta_add"
  echo "DELTA_RM=$delta_rm"
  echo "AFFECTED_BUCKETS=$affected_buckets"
  echo "OLD_BUCKET_COUNT=$old_bucket_count"
  echo "NEW_BUCKET_COUNT=$new_bucket_count"
  echo "OBSERVED_DELTA=$observed_delta"
  echo "MCONF_GZIP_BYTES=$mconf_gzip_bytes"
  echo "MCONF_KB=$mconf_kb"
  echo "LOCK_CT_BYTES=$lock_ct_bytes"
  echo "LOCK_CT_KB=$lock_ct_kb"
  echo "MCONF_GENERATE_MS=$mconf_generate_ms"
  echo "RESOLVE_ROOT_VERSIONS_MS=$resolve_roots_ms"
  echo "LOCK_REFRESH_MS=$lock_refresh_ms"
  echo "OBJECT_BUILD_MS=$object_build_ms"
  echo "IPFS_ADD_LOCK_ROOT_MS=$ipfs_add_ms"
  echo "BLOCKCHAIN_REGISTER_MS=$blockchain_ms"
  echo "POLICY_UPDATE_SIX_STAGE_SUM_MS=$six_stage_sum_ms"
  echo "POLICY_UPDATE_TOTAL_MS=$total_ms"
  echo "POLICY_UPDATE_CORE_WALL_MS=$core_wall_ms"
  echo "POLICY_UPDATE_WALL_EXCL_POLICY_GEN_MS=$update_wall_ms"
  echo "POLICY_UPDATE_WALL_GAP_MS=$wall_gap_ms"
  echo "POLICY_UPDATE_WALL_GAP_PCT=$wall_gap_pct"
  echo "DIAG_POLICY_UPDATE_E2E_EXCL_POLICY_GEN_MS=$update_e2e_ms"
  echo "PROGRAM_WALL_MS=$program_wall_ms"
  echo "PROGRAM_WALL_MINUS_SIX_STAGES_MS=$program_wall_gap_ms"
  echo "PROGRAM_WALL_MINUS_SIX_STAGES_PCT=$program_wall_gap_pct"
  echo "DATA_CID_REUSED=${data_cid_reused:-NA}"
  echo "DIAG_POLICY_GEN_EXCLUDED_MS=${policy_gen_ms:-NA}"
  echo "DIAG_PROGRAM_BOOTSTRAP_MS=$program_bootstrap_ms"
  echo "DIAG_STATE_PREPARE_MS=${state_prepare_ms:-NA}"
  echo "DIAG_LOCAL_PERSIST_MS=${local_persist_ms:-NA}"
  echo "DIAG_POST_PROCESS_MS=$post_process_ms"
  echo "DIAG_CLIENT_ARTIFACT_WRITE_MS=$client_artifact_write_ms"
  echo "DIAG_UNATTRIBUTED_GAP_MS=${unattributed_gap_ms:-NA}"
  echo "================= EXPERIMENT_SUMMARY_END ================="
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

make_proof_for_request () {
  local cid="$1"
  local requester="$2"
  local provider="$3"
  local requester_pid="$4"

  echo "== out-of-band zk proof generation on $requester =="
  echo "Proof target: cid=$cid requester_pid=$requester_pid"

  local prove_out
  prove_out=$(docker exec -w "$CMD_DIR" "$requester" "$CMD_DIR/dataRetrieve" prove "$cid" "$requester_pid" "$requester")
  echo "$prove_out"

  local proof_path
  proof_path=$(parse_proof_bundle_path "$prove_out")
  if [ -z "$proof_path" ]; then
    echo "ERROR: failed to parse PROOF_BUNDLE_PATH from dataRetrieve prove output"
    exit 1
  fi

  local proof_dir
  local proof_base
  proof_dir=$(dirname "$proof_path")
  proof_base=$(basename "$proof_path")

  echo "Synchronizing proof bundle to provider $provider: $proof_path"
  local tmp_dir
  tmp_dir=$(mktemp -d)
  docker cp "$requester:$proof_path" "$tmp_dir/$proof_base"
  docker exec "$provider" sh -lc "mkdir -p '$proof_dir'"
  docker cp "$tmp_dir/$proof_base" "$provider:$proof_path"
  rm -rf "$tmp_dir"

  echo "Provider proof bundle check on $provider:"
  docker exec "$provider" sh -lc "test -s '$proof_path' && ls -lh '$proof_path'"
}

check_hash_equal () {
  local file1="$1"
  local file2="$2"
  local h1
  local h2

  h1=$(docker exec "$EVE" sh -lc "sha256sum $file1 | awk '{print \$1}'")
  h2=$(docker exec "$EVE" sh -lc "sha256sum $file2 | awk '{print \$1}'")

  echo "hash($file1) = $h1"
  echo "hash($file2) = $h2"

  if [ "$h1" != "$h2" ]; then
    echo "ERROR: hash mismatch between $file1 and $file2"
    exit 1
  fi
}

collect_dag_refs_on_node () {
  local node="$1"
  local cid="$2"
  local out_file="$3"

  docker exec "$node" sh -lc "
    rm -f $out_file
    ipfs refs -r $cid > $out_file 2>/dev/null || true
    echo $cid >> $out_file
    sort -u $out_file -o $out_file
    echo \"refs($cid) = \$(wc -l < $out_file)\"
  "
}

dag_reuse_stats_on_node () {
  local node="$1"
  local old_refs="$2"
  local new_refs="$3"

  docker exec "$node" sh -lc "
    rm -f /tmp/polylock_shared_refs.txt /tmp/polylock_newonly_refs.txt

    comm -12 $old_refs $new_refs > /tmp/polylock_shared_refs.txt || true
    comm -13 $old_refs $new_refs > /tmp/polylock_newonly_refs.txt || true

    old_blocks=\$(wc -l < $old_refs)
    new_blocks=\$(wc -l < $new_refs)
    shared_blocks=\$(wc -l < /tmp/polylock_shared_refs.txt)
    newonly_blocks=\$(wc -l < /tmp/polylock_newonly_refs.txt)

    newonly_bytes=0
    while read b; do
      if [ -n \"\$b\" ]; then
        sz=\$(ipfs block stat \"\$b\" 2>/dev/null | awk '/Size:/ {print \$2}')
        if [ -n \"\$sz\" ]; then
          newonly_bytes=\$((newonly_bytes + sz))
        fi
      fi
    done < /tmp/polylock_newonly_refs.txt

    echo \"OLD_BLOCKS=\$old_blocks\"
    echo \"NEW_BLOCKS=\$new_blocks\"
    echo \"SHARED_BLOCKS=\$shared_blocks\"
    echo \"NEW_ONLY_BLOCKS=\$newonly_blocks\"
    echo \"NEW_ONLY_BYTES=\$newonly_bytes\"
  "
}

# ============================================================
# 2.1 Reset and start all IPFS nodes
# ============================================================

echo "reset and update ipfs......"

for node in "${nodes[@]}"; do
  reset_ipfs_node "$node"
done

connect_all_ipfs_nodes

echo "checking daemon state after reset......"
for node in "${nodes[@]}"; do
  echo "== $node daemon check =="
  docker exec "$node" sh -lc "pgrep -af '[i]pfs daemon' || true"
  docker exec "$node" sh -lc "ipfs id -f='<id>\n'"
done

# ============================================================
# 3) systemInit: universal setup + global admissible space S* + user registration
# ============================================================

ipfs_nodes=("$ALICE" "$EVE")

echo "== 1) systemInit each node: generate/register global S* and user state =="
for node in "${ipfs_nodes[@]}"; do
  PID=$(peer_id_of "$node")
  echo "systemInit for $node  PID=$PID"
  INIT_OUT=$(docker exec -w "$CMD_DIR" "$node" "$CMD_DIR/systemInit" "$node" "/root/.ipfs/config")
  echo "$INIT_OUT"

  # The system-level comparison measures registration after global setup.
  # Use Eve as the representative requester and exclude CircuitGen, UniSetup,
  # and admissible-space generation from the registration result.
  if [ "$node" = "$EVE" ]; then
    SYSTEM_INIT_WALL_MS=$(parse_ms_field "$INIT_OUT" "SystemInit")
    UNIVERSAL_SETUP_MS=$(parse_ms_field "$INIT_OUT" "UniversalSetup")
    PROFILE_SPACE_MS=$(parse_ms_field "$INIT_OUT" "ProfileSpace")
    SUMMARY_USER_REGISTER_ZKGUARD_MS=$(parse_ms_field "$INIT_OUT" "UserRegister")
    SUMMARY_USER_REGISTER_POLYLOCK_MS=$(parse_ms_field "$INIT_OUT" "PolyLockKeyGen")
    SUMMARY_USER_REGISTER_TOTAL_MS=$(subtract_ms_values \
      "$SYSTEM_INIT_WALL_MS" \
      "$UNIVERSAL_SETUP_MS" \
      "$PROFILE_SPACE_MS")
    USER_REGISTER_CORE_SUM_MS=$(sum_ms_values \
      "$SUMMARY_USER_REGISTER_ZKGUARD_MS" \
      "$SUMMARY_USER_REGISTER_POLYLOCK_MS")
    SUMMARY_USER_REGISTER_SUPPORT_MS=$(subtract_ms_values \
      "$SUMMARY_USER_REGISTER_TOTAL_MS" \
      "$USER_REGISTER_CORE_SUM_MS")
  fi

  #echo "-- $node system config --"
  #docker exec -w "$CMD_DIR" "$node" sh -lc "test -f polylock_state/system/system_config.json && cat polylock_state/system/system_config.json | head -n 40 || true"
done

if [ "$SUMMARY_USER_REGISTER_TOTAL_MS" = "NA" ]; then
  echo "ERROR: failed to parse user-registration metrics from systemInit output"
  exit 1
fi

# Prepare the same minimal one-byte linked object on the data owner and
# requester. The requester-side copy is used only for plaintext hash checking.
echo "== prepare minimal linked object =="
for node in "$ALICE" "$EVE"; do
  docker exec "$node" sh -lc "
    printf 'x' > '$TEST_OBJECT_PATH'
    test \"\$(wc -c < '$TEST_OBJECT_PATH')\" -eq 1
  "
done

# ============================================================
# 4) Data storage: Alice encrypts/uploads/registers a two-link RootCID
# ============================================================

echo "== 2) dataStorage on Alice: S*-based PolicyGen + PolyLock encrypt + chain registration =="
APID=$(peer_id_of "$ALICE")

STORAGE_OUT=$(docker exec -w "$CMD_DIR" "$ALICE" "$CMD_DIR/dataStorage" "$TEST_OBJECT_PATH" "$APID" "$ALICE")
echo "$STORAGE_OUT"

SUMMARY_DATA_OBJECT_BYTES=$(docker exec "$ALICE" sh -lc "wc -c < '$TEST_OBJECT_PATH'" | tr -d '\r' | tr -d ' ')
SUMMARY_STORAGE_POLICY_ENCODE_MS=$(parse_ms_field "$STORAGE_OUT" "encodePolicy")
SUMMARY_STORAGE_POLYLOCK_MS=$(parse_ms_field "$STORAGE_OUT" "polylockStorage")
SUMMARY_STORAGE_BLOCKCHAIN_MS=$(parse_ms_field "$STORAGE_OUT" "blockchainStorage")
SUMMARY_STORAGE_TOTAL_MS=$(sum_ms_values \
  "$SUMMARY_STORAGE_POLICY_ENCODE_MS" \
  "$SUMMARY_STORAGE_POLYLOCK_MS" \
  "$SUMMARY_STORAGE_BLOCKCHAIN_MS")

if [ "$SUMMARY_STORAGE_TOTAL_MS" = "NA" ]; then
  echo "ERROR: failed to parse complete data-storage metrics"
  exit 1
fi
CID=$(parse_cid_from_storage "$STORAGE_OUT")
if [ -z "$CID" ]; then
  CID=$(parse_cid_fallback "$STORAGE_OUT")
fi
if [ -z "$CID" ]; then
  echo "ERROR: failed to parse RootCID from dataStorage output"
  exit 1
fi

#echo "CID = $CID"
#docker exec "$ALICE" sh -lc "echo Root object links: && ipfs ls $CID || true"
#docker exec "$ALICE" sh -lc "ipfs refs -r $CID > /tmp/root_refs.txt && wc -l /tmp/root_refs.txt"

# ============================================================
# 5) Out-of-band proof generation + native IPFS retrieval.
#    Eve generates the ZK proof locally and writes a minimal proof bundle
#    containing only ProofB64/SigB64/PubKeyPEM. The bundle is synchronized to
#    Alice so that the provider-side dataRetrieve can verify without proving.
# ============================================================

#sleep 5
#ensure_provider_and_connection "$CID"

echo "== 3) ipfs get encrypted two-link object on Eve =="
RETRIEVE_START_MS=$(now_ms)

docker exec "$EVE" sh -lc "rm -rf /root/ls_obj /root/ls_retrieved.bin"

# PeerID is stable after IPFS initialization and is resolved outside the
# proof-exchange timing interval.
REQUESTER_PID=$(peer_id_of "$EVE")
if [ -z "$REQUESTER_PID" ]; then
  echo "ERROR: failed to resolve requester PeerID for $EVE"
  exit 1
fi

PROOF_START_MS=$(now_ms)
make_proof_for_request "$CID" "$EVE" "$ALICE" "$REQUESTER_PID"
PROOF_END_MS=$(now_ms)

IPFS_GET_START_MS=$(now_ms)
ipfs_get_or_fail "$EVE" "$CID" "/root/ls_obj" "$GET_TIMEOUT"
IPFS_GET_END_MS=$(now_ms)

CHECK_OBJECT_START_MS=$(now_ms)
docker exec "$EVE" sh -lc "find /root/ls_obj -maxdepth 2 -type f -print -exec ls -lh {} \;"
docker exec "$EVE" sh -lc "test -f /root/ls_obj/data.ct && test -f /root/ls_obj/lock.ct"
CHECK_OBJECT_END_MS=$(now_ms)

echo "== 4) PolyLock local decrypt on Eve =="
DECRYPT_START_MS=$(now_ms)
DECRYPT_OUT=$(docker exec -w "$CMD_DIR" "$EVE" "$CMD_DIR/dataDecrypt" "/root/ls_obj" "$EVE" "/root/ls_retrieved.bin")
echo "$DECRYPT_OUT"
DECRYPT_END_MS=$(now_ms)

RETRIEVE_END_MS=$(now_ms)
SUMMARY_RETRIEVE_PROOF_EXCHANGE_MS=$((PROOF_END_MS - PROOF_START_MS))
SUMMARY_RETRIEVE_IPFS_GET_MS=$((IPFS_GET_END_MS - IPFS_GET_START_MS))
SUMMARY_RETRIEVE_POLYLOCK_DECRYPT_MS=$((DECRYPT_END_MS - DECRYPT_START_MS))
SUMMARY_RETRIEVE_TOTAL_MS=$(sum_ms_values \
  "$SUMMARY_RETRIEVE_PROOF_EXCHANGE_MS" \
  "$SUMMARY_RETRIEVE_IPFS_GET_MS" \
  "$SUMMARY_RETRIEVE_POLYLOCK_DECRYPT_MS")
echo "============== Retrieval timing (ms) =============="
echo "PROOF_EXCHANGE_MS        = $SUMMARY_RETRIEVE_PROOF_EXCHANGE_MS ms"
echo "IPFS_GET_MS              = $SUMMARY_RETRIEVE_IPFS_GET_MS ms"
echo "OBJECT_CHECK_MS          = $((CHECK_OBJECT_END_MS - CHECK_OBJECT_START_MS)) ms"
echo "POLYLOCK_DECRYPT_STEP_MS = $SUMMARY_RETRIEVE_POLYLOCK_DECRYPT_MS ms"
echo "RETRIEVE_TOTAL_MS        = $SUMMARY_RETRIEVE_TOTAL_MS ms"
echo "RETRIEVE_WALL_WITH_TEST_CHECK_MS = $((RETRIEVE_END_MS - RETRIEVE_START_MS)) ms"
echo "==================================================="

echo "== 4.1) Verify decrypted plaintext =="
check_hash_equal "/root/ls_retrieved.bin" "$TEST_OBJECT_PATH"

echo "CID=$CID has been retrieved through native IPFS and locally decrypted by PolyLock."

# ============================================================
# 6) True policy update: new policy over S*, new mconf, partial lock refresh.
#    No configured affected-ratio is passed. The program reports observed ratio.
# ============================================================

echo "== 5) policyUpdate on Alice: true end-to-end double-layer policy update =="
APID=$(peer_id_of "$ALICE")

UPDATE_OUT=$(docker exec -w "$CMD_DIR" "$ALICE" "$CMD_DIR/policyUpdate" "$CID" "$APID" "$ALICE")
echo "$UPDATE_OUT"

POLICY_TOTAL_MS=$(parse_eq_field "$UPDATE_OUT" "POLICY_UPDATE_TOTAL_MS")
SUMMARY_POLICY_UPDATE_TOTAL_MS="${POLICY_TOTAL_MS:-NA}"
POLICY_OBSERVED_RATIO=$(parse_eq_field "$UPDATE_OUT" "OBSERVED_DELTA")
SUMMARY_POLICY_OBSERVED_DELTA="${POLICY_OBSERVED_RATIO:-NA}"
SUMMARY_POLICY_DELTA_ADD=$(parse_eq_field "$UPDATE_OUT" "DELTA_ADD")
SUMMARY_POLICY_DELTA_RM=$(parse_eq_field "$UPDATE_OUT" "DELTA_RM")
SUMMARY_ATTR_NUM=$(parse_eq_field "$UPDATE_OUT" "ATTR_NUM")
SUMMARY_LEGAL_SPACE_SIZE=$(parse_eq_field "$UPDATE_OUT" "LEGAL_SPACE_SIZE")
SUMMARY_TARGET_SIGMA=$(parse_eq_field "$UPDATE_OUT" "TARGET_SIGMA")
POLICY_IPFS_ADD_MS=$(parse_eq_field "$UPDATE_OUT" "IPFS_ADD_LOCK_ROOT_MS")
POLICY_AFFECTED_BUCKETS=$(parse_value_field "$UPDATE_OUT" "Affected buckets")
POLICY_PARTIAL_REFRESH_MS=$(parse_eq_field "$UPDATE_OUT" "LOCK_REFRESH_MS")
SUMMARY_POLICY_BUCKET_REFRESH_MS="${POLICY_PARTIAL_REFRESH_MS:-NA}"
POLICYGEN_EXCLUDED_MS=$(parse_eq_field "$UPDATE_OUT" "POLICY_GEN_EXCLUDED_MS")
NEW_CID=$(parse_new_root_cid "$UPDATE_OUT")

if [ -z "$NEW_CID" ]; then
  echo "ERROR: failed to parse NEW_ROOT_CID from policyUpdate output"
  exit 1
fi

echo "OLD_CID = $CID"
echo "NEW_CID = $NEW_CID"
echo "POLICY_TOTAL_MS = $POLICY_TOTAL_MS ms"
#echo "POLICY_OBSERVED_RATIO = $POLICY_OBSERVED_RATIO"
echo "POLICY_AFFECTED_BUCKETS = $POLICY_AFFECTED_BUCKETS"
echo "POLICY_IPFS_ADD_MS = $POLICY_IPFS_ADD_MS ms"
echo "POLICY_PARTIAL_REFRESH_MS = $POLICY_PARTIAL_REFRESH_MS ms"
echo "POLICYGEN_EXCLUDED_MS = $POLICYGEN_EXCLUDED_MS ms"

docker exec "$ALICE" sh -lc "echo Updated root object links: && ipfs ls $NEW_CID || true"
CID="$NEW_CID"

# ============================================================
# 7) Retrieve updated object through native IPFS and decrypt locally
# ============================================================

sleep 3
ensure_provider_and_connection "$CID"

echo "== 6) ipfs get updated encrypted object on Eve =="
RETRIEVE_AFTER_POLICY_START_MS=$(now_ms)

docker exec "$EVE" sh -lc "rm -rf /root/ls_after_policy_obj /root/ls_after_policy.bin"

PROOF_AFTER_POLICY_START_MS=$(now_ms)
make_proof_for_request "$CID" "$EVE" "$ALICE" "$REQUESTER_PID"
PROOF_AFTER_POLICY_END_MS=$(now_ms)

IPFS_GET_AFTER_POLICY_START_MS=$(now_ms)
ipfs_get_or_fail "$EVE" "$CID" "/root/ls_after_policy_obj" "$GET_TIMEOUT"
IPFS_GET_AFTER_POLICY_END_MS=$(now_ms)

CHECK_OBJECT_AFTER_POLICY_START_MS=$(now_ms)
docker exec "$EVE" sh -lc "find /root/ls_after_policy_obj -maxdepth 2 -type f -print -exec ls -lh {} \;"
docker exec "$EVE" sh -lc "test -f /root/ls_after_policy_obj/data.ct && test -f /root/ls_after_policy_obj/lock.ct"
CHECK_OBJECT_AFTER_POLICY_END_MS=$(now_ms)

echo "== 7) PolyLock local decrypt after policyUpdate =="
DECRYPT_AFTER_POLICY_START_MS=$(now_ms)
docker exec -w "$CMD_DIR" "$EVE" "$CMD_DIR/dataDecrypt" "/root/ls_after_policy_obj" "$EVE" "/root/ls_after_policy.bin"
docker exec "$EVE" ls -lh /root/ls_after_policy.bin
DECRYPT_AFTER_POLICY_END_MS=$(now_ms)

RETRIEVE_AFTER_POLICY_END_MS=$(now_ms)
echo "============== Retrieval timing after policyUpdate (ms) =============="
echo "PROOF_EXCHANGE_AFTER_POLICY_MS        = $((PROOF_AFTER_POLICY_END_MS - PROOF_AFTER_POLICY_START_MS)) ms"
echo "IPFS_GET_AFTER_POLICY_MS              = $((IPFS_GET_AFTER_POLICY_END_MS - IPFS_GET_AFTER_POLICY_START_MS)) ms"
echo "OBJECT_CHECK_AFTER_POLICY_MS          = $((CHECK_OBJECT_AFTER_POLICY_END_MS - CHECK_OBJECT_AFTER_POLICY_START_MS)) ms"
echo "POLYLOCK_DECRYPT_AFTER_POLICY_STEP_MS = $((DECRYPT_AFTER_POLICY_END_MS - DECRYPT_AFTER_POLICY_START_MS)) ms"
echo "RETRIEVE_AFTER_POLICY_TOTAL_MS        = $((RETRIEVE_AFTER_POLICY_END_MS - RETRIEVE_AFTER_POLICY_START_MS)) ms"
echo "======================================================================"

echo "== 7.1) Verify decrypted plaintext after policyUpdate =="
check_hash_equal "/root/ls_after_policy.bin" "$TEST_OBJECT_PATH"

# ============================================================
# 8) Large-file reuse benchmark under true policy update
#    Goal: verify that policyUpdate reuses existing data ciphertext blocks
#          and only publishes a refreshed lock.ct plus a tiny root DAG delta.
# ============================================================

if [ "$RUN_LARGE_BENCH" = "1" ]; then

echo "== 8) Large-file PolicyUpdate reuse benchmark =="

echo "Preparing large random file on Alice: $LARGE_FILE"
docker exec "$ALICE" sh -lc "
  LARGE_FILE=\"$LARGE_FILE\"
  LARGE_SIZE_BYTES=\"$LARGE_SIZE_BYTES\"

  if [ -f \"\$LARGE_FILE\" ]; then
    CUR_SIZE=\$(wc -c < \"\$LARGE_FILE\" | tr -d ' ')
  else
    CUR_SIZE=0
  fi

  if [ ! -f \"\$LARGE_FILE\" ] || [ \"\$CUR_SIZE\" -ne \"\$LARGE_SIZE_BYTES\" ]; then
    echo \"Generating large random file. This may take a while...\"
    rm -f \"\$LARGE_FILE\"
    dd if=/dev/urandom of=\"\$LARGE_FILE\" bs=4M count=\$((LARGE_SIZE_BYTES / 4194304))
    sync
  else
    echo \"Large random file already exists and size is correct.\"
  fi

  ls -lh \"\$LARGE_FILE\"
  echo \"File size bytes: \$(wc -c < \"\$LARGE_FILE\" | tr -d ' ')\"
"

APID=$(peer_id_of "$ALICE")

echo "== 8.1) dataStorage for large file =="
LARGE_STORAGE_OUT=$(docker exec -w "$CMD_DIR" "$ALICE" sh -lc "timeout $LARGE_TIMEOUT $CMD_DIR/dataStorage $LARGE_FILE $APID $ALICE")
echo "$LARGE_STORAGE_OUT"

LARGE_OLD_CID=$(parse_cid_from_storage "$LARGE_STORAGE_OUT")
if [ -z "$LARGE_OLD_CID" ]; then
  LARGE_OLD_CID=$(parse_cid_fallback "$LARGE_STORAGE_OUT")
fi
if [ -z "$LARGE_OLD_CID" ]; then
  echo "ERROR: failed to parse LARGE_OLD_CID from dataStorage output"
  exit 1
fi

FULL_STORAGE_MS=$(parse_ms_field "$LARGE_STORAGE_OUT" "polylockStorage")
FULL_IPFS_ADD_MS=$(parse_ms_field "$LARGE_STORAGE_OUT" "IPFSAddTime")

echo "LARGE_OLD_CID = $LARGE_OLD_CID"
echo "FULL_STORAGE_MS = $FULL_STORAGE_MS ms"
echo "FULL_IPFS_ADD_MS = $FULL_IPFS_ADD_MS ms"

echo "Collecting old DAG refs..."
collect_dag_refs_on_node "$ALICE" "$LARGE_OLD_CID" "/tmp/polylock_large_old_refs.txt"

echo "== 8.2) true policyUpdate for large object =="
LARGE_UPDATE_OUT=$(docker exec -w "$CMD_DIR" "$ALICE" sh -lc "timeout $LARGE_TIMEOUT $CMD_DIR/policyUpdate $LARGE_OLD_CID $APID $ALICE")
echo "$LARGE_UPDATE_OUT"

LARGE_NEW_CID=$(parse_new_root_cid "$LARGE_UPDATE_OUT")
if [ -z "$LARGE_NEW_CID" ]; then
  echo "ERROR: failed to parse LARGE_NEW_CID from policyUpdate output"
  exit 1
fi

LARGE_POLICY_TOTAL_MS=$(parse_eq_field "$LARGE_UPDATE_OUT" "POLICY_UPDATE_TOTAL_MS")
LARGE_POLICY_OBSERVED_RATIO=$(parse_eq_field "$LARGE_UPDATE_OUT" "OBSERVED_DELTA")
LARGE_POLICY_IPFS_ADD_MS=$(parse_eq_field "$LARGE_UPDATE_OUT" "IPFS_ADD_LOCK_ROOT_MS")
LARGE_AFFECTED_BUCKETS=$(parse_value_field "$LARGE_UPDATE_OUT" "Affected buckets")

echo "LARGE_OLD_CID = $LARGE_OLD_CID"
echo "LARGE_NEW_CID = $LARGE_NEW_CID"
echo "LARGE_POLICY_TOTAL_MS = $LARGE_POLICY_TOTAL_MS ms"
#echo "LARGE_POLICY_OBSERVED_RATIO = $LARGE_POLICY_OBSERVED_RATIO"
echo "LARGE_AFFECTED_BUCKETS = $LARGE_AFFECTED_BUCKETS"
echo "LARGE_POLICY_IPFS_ADD_MS = $LARGE_POLICY_IPFS_ADD_MS ms"

echo "Collecting new DAG refs..."
collect_dag_refs_on_node "$ALICE" "$LARGE_NEW_CID" "/tmp/polylock_large_new_refs.txt"

echo "== 8.3) DAG reuse statistics =="
DAG_STATS_OUT=$(dag_reuse_stats_on_node "$ALICE" "/tmp/polylock_large_old_refs.txt" "/tmp/polylock_large_new_refs.txt")
echo "$DAG_STATS_OUT"
LARGE_NEW_ONLY_BYTES=$(parse_eq_field "$DAG_STATS_OUT" "NEW_ONLY_BYTES")

echo "== 8.4) Large-file summary =="
echo "FULL_STORAGE_MS            = $FULL_STORAGE_MS ms"
echo "LARGE_POLICY_TOTAL_MS      = $LARGE_POLICY_TOTAL_MS ms"
#echo "LARGE_POLICY_OBSERVED_RATIO= $LARGE_POLICY_OBSERVED_RATIO"
echo "LARGE_POLICY_IPFS_ADD_MS    = $LARGE_POLICY_IPFS_ADD_MS ms"
echo "Expected result            = policyUpdate should reuse the old DataCID; NEW_ONLY_BYTES should be far smaller than the large data file."

  SUMMARY_LARGE_STORAGE_MS="${FULL_STORAGE_MS:-0}"
  SUMMARY_LARGE_POLICY_TOTAL_MS="${LARGE_POLICY_TOTAL_MS:-0}"
  SUMMARY_LARGE_NEW_ONLY_BYTES="${LARGE_NEW_ONLY_BYTES:-0}"
else
  echo "== 8) Large-file PolicyUpdate reuse benchmark skipped =="
  echo "Set RUN_LARGE_BENCH=1 to enable this section."
fi

# ============================================================
# 9) Attribute update on Eve
#    The affected user count is the experiment parameter R.
# ============================================================

echo "== 9) AttributeUpdate on Eve, affected users = $AFFECTED_USERS =="
ATTR_OUT=$(docker exec -w "$CMD_DIR" "$EVE" "$CMD_DIR/attributeUpdate" "/root/.ipfs/config" "$EVE" "$AFFECTED_USERS")
echo "$ATTR_OUT"

# attributeUpdate_random_timing.go now prints these five dedicated metrics.
# Do not compute LocalCommitRefresh by residual, otherwise profile-space loading,
# Fabric connection, and debug queries may be incorrectly included.
LOCAL_COMMIT_REFRESH_MS=$(parse_metric_ms "$ATTR_OUT" "LOCAL_COMMIT_REFRESH_MS")
CHAIN_ATTRIBUTE_UPDATE_MS=$(parse_metric_ms "$ATTR_OUT" "CHAIN_ATTRIBUTE_UPDATE_MS")
POLYLOCK_KEYGEN_TOTAL_MS=$(parse_metric_ms "$ATTR_OUT" "POLYLOCK_KEYGEN_TOTAL_MS")
ATTRIBUTE_UPDATE_TOTAL_MS=$(parse_metric_ms "$ATTR_OUT" "ATTRIBUTE_UPDATE_TOTAL_MS")
ATTRIBUTE_UPDATE_WALL_MS=$(parse_metric_ms "$ATTR_OUT" "ATTRIBUTE_UPDATE_WALL_MS")

missing_metric=0
for metric_name in LOCAL_COMMIT_REFRESH_MS CHAIN_ATTRIBUTE_UPDATE_MS POLYLOCK_KEYGEN_TOTAL_MS ATTRIBUTE_UPDATE_TOTAL_MS ATTRIBUTE_UPDATE_WALL_MS; do
  metric_value="${!metric_name:-}"
  if [ -z "$metric_value" ] || [ "$metric_value" = "NA" ]; then
    echo "ERROR: missing metric $metric_name from attributeUpdate output."
    echo "Please make sure attributeUpdate/main.go has been replaced by attributeUpdate_random_timing.go and rebuilt."
    missing_metric=1
  fi
done
if [ "$missing_metric" -ne 0 ]; then
  exit 1
fi

ATTRIBUTE_UPDATE_SUM_CHECK_MS=$(awk   -v a="$LOCAL_COMMIT_REFRESH_MS"   -v b="$CHAIN_ATTRIBUTE_UPDATE_MS"   -v c="$POLYLOCK_KEYGEN_TOTAL_MS"   'BEGIN { printf "%.3f", a+b+c }')
ATTRIBUTE_UPDATE_SUM_DIFF_MS=$(awk   -v s="$ATTRIBUTE_UPDATE_SUM_CHECK_MS"   -v t="$ATTRIBUTE_UPDATE_TOTAL_MS"   'BEGIN { d=s-t; if (d<0) d=-d; printf "%.3f", d }')

echo "== 9.1) AttributeUpdate parsed metrics =="
echo "LOCAL_COMMIT_REFRESH_MS    = ${LOCAL_COMMIT_REFRESH_MS} ms"
echo "CHAIN_ATTRIBUTE_UPDATE_MS  = ${CHAIN_ATTRIBUTE_UPDATE_MS} ms"
echo "POLYLOCK_KEYGEN_TOTAL_MS   = ${POLYLOCK_KEYGEN_TOTAL_MS} ms"
echo "ATTRIBUTE_UPDATE_TOTAL_MS  = ${ATTRIBUTE_UPDATE_TOTAL_MS} ms"
echo "ATTRIBUTE_UPDATE_WALL_MS   = ${ATTRIBUTE_UPDATE_WALL_MS} ms"
echo "ATTRIBUTE_UPDATE_SUM_CHECK_MS = ${ATTRIBUTE_UPDATE_SUM_CHECK_MS} ms"
echo "ATTRIBUTE_UPDATE_SUM_DIFF_MS  = ${ATTRIBUTE_UPDATE_SUM_DIFF_MS} ms"

print_system_comparison_experiment_summary

echo "=== 自动化测试完成 ==="
