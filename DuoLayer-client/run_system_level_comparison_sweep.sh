#!/usr/bin/env bash

set -Eeuo pipefail

# 系统级端到端批量实验：
#   N = 100, 200, 300, 500, 800；
#   固定 sigma = 0.8；
#   固定属性更新受影响用户数 R = 100；
#   合法属性空间规模由系统设置为 |S*| = 10N。
#
# 每轮均独立执行：
#   start_fabric_zkguard.sh 1000 25 down
#   start_fabric_zkguard.sh N 4 up 0.8 10N
#   test_ipfs_cluster.sh --attr-num N --legal-space-size 10N ...
#
# 用法：
#   ./run_system_level_comparison_sweep.sh [每个参数点的重复次数]
#
# 示例：
#   ./run_system_level_comparison_sweep.sh 5
#   REPEATS=10 ./run_system_level_comparison_sweep.sh
#
# 可选环境变量：
#   RESULT_ROOT=/path/to/results  指定本次实验结果目录；
#   DATA_OBJECT_FILE=/path/to/tif 指定完整的真实地学数据对象；
#   COOLDOWN_SECONDS=5            两轮之间的等待秒数；
#   CONTINUE_ON_ERROR=1           单轮失败后继续，默认遇错停止。

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# 非交互式 SSH 会话未必继承 Go/Rust 工具链路径；显式加入服务器的标准安装位置。
export PATH="/usr/local/go/bin:/root/.cargo/bin:$PATH"
START_SCRIPT="$SCRIPT_DIR/start_fabric_zkguard.sh"
TEST_SCRIPT="$SCRIPT_DIR/test_ipfs_cluster.sh"
CONFIGTX_FILE="$SCRIPT_DIR/../configtx/configtx.yaml"
EXPERIMENT_BATCH_TIMEOUT="${EXPERIMENT_BATCH_TIMEOUT:-1ms}"

REPEATS="${1:-${REPEATS:-5}}"
COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-5}"
CONTINUE_ON_ERROR="${CONTINUE_ON_ERROR:-0}"

DOWN_ATTR_COUNT=1000
DOWN_ORG_COUNT=25
UP_ORG_COUNT=4
FIXED_SIGMA=0.8
AFFECTED_USERS=100
DATA_OBJECT_FILE="${DATA_OBJECT_FILE:-$SCRIPT_DIR/geodata/LC08_L2SP_002059_20240915_20240921_02_T1_QA_PIXEL.TIF}"
if [ ! -f "$DATA_OBJECT_FILE" ] || [ ! -r "$DATA_OBJECT_FILE" ]; then
  echo "ERROR: 地学数据对象不存在或不可读: $DATA_OBJECT_FILE" >&2
  exit 2
fi
DATA_OBJECT_BYTES=$(stat -c '%s' "$DATA_OBJECT_FILE")
DATA_OBJECT_SHA256=$(sha256sum "$DATA_OBJECT_FILE" | awk '{print $1}')
ATTR_VALUES=(100 200 300 500 800)

RUN_STAMP=$(date '+%Y%m%d_%H%M%S')
RESULT_ROOT="${RESULT_ROOT:-$SCRIPT_DIR/system_comparison_results/$RUN_STAMP}"
RAW_DIR="$RESULT_ROOT/raw_logs"
SUMMARY_DIR="$RESULT_ROOT/summaries"
ALL_AGGREGATE="$RESULT_ROOT/system_level_all_summaries.txt"
MEASUREMENTS="$RESULT_ROOT/system_level_measurements.tsv"
MANIFEST="$RESULT_ROOT/manifest.tsv"

CURRENT_NETWORK_UP=0
BATCH_TIMEOUT_CHANGED=0
LAST_FAILURE_STAGE=""
LAST_SUMMARY_FILE=""
LAST_TEST_LOG=""

if ! [[ "$REPEATS" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: 重复次数必须是正整数，当前值为: $REPEATS" >&2
  exit 2
fi
if ! [[ "$COOLDOWN_SECONDS" =~ ^[0-9]+$ ]]; then
  echo "ERROR: COOLDOWN_SECONDS 必须是非负整数。" >&2
  exit 2
fi
if [ "$CONTINUE_ON_ERROR" != "0" ] && [ "$CONTINUE_ON_ERROR" != "1" ]; then
  echo "ERROR: CONTINUE_ON_ERROR 只能取 0 或 1。" >&2
  exit 2
fi
if [ ! -x "$START_SCRIPT" ]; then
  echo "ERROR: 找不到可执行脚本 $START_SCRIPT" >&2
  exit 2
fi
if [ ! -x "$TEST_SCRIPT" ]; then
  echo "ERROR: 找不到可执行脚本 $TEST_SCRIPT" >&2
  exit 2
fi

mkdir -p "$RAW_DIR" "$SUMMARY_DIR"
: > "$ALL_AGGREGATE"
printf '%s\n' \
  $'attr_num\tlegal_space_size\tsigma\taffected_users\trun\tdata_object_bytes\tuser_register_zkguard_ms\tuser_register_polylock_keygen_ms\tuser_register_support_ms\tuser_register_total_ms\tdata_storage_policy_encode_ms\tdata_storage_polylock_ms\tdata_storage_blockchain_ms\tdata_storage_total_ms\tdata_retrieve_proof_exchange_ms\tdata_retrieve_ipfs_get_ms\tdata_retrieve_polylock_decrypt_ms\tdata_retrieve_total_ms\tpolicy_update_total_ms\tpolicy_update_observed_delta\tpolicy_update_delta_add\tpolicy_update_delta_rm\tattribute_update_total_ms' \
  > "$MEASUREMENTS"
printf '%s\n' \
  $'attr_num\tsigma\taffected_users\trun\tstatus\tfailure_stage\tduration_s\tsummary_file\ttest_log' \
  > "$MANIFEST"

run_logged() {
  local label="$1"
  local log_file="$2"
  shift 2

  echo "[$(date '+%F %T')] $label"
  if "$@" > "$log_file" 2>&1; then
    return 0
  fi

  echo "ERROR: $label 失败，日志: $log_file" >&2
  tail -n 50 "$log_file" >&2 || true
  return 1
}

read_batch_timeout() {
  awk '$1 == "BatchTimeout:" { print $2; exit }' "$CONFIGTX_FILE"
}

set_batch_timeout() {
  local value="$1"
  sed -i -E "s/^([[:space:]]*BatchTimeout:)[[:space:]]*.*/\\1 ${value}/" "$CONFIGTX_FILE"
}

ORIGINAL_BATCH_TIMEOUT=$(read_batch_timeout)
if [ -z "$ORIGINAL_BATCH_TIMEOUT" ]; then
  echo "ERROR: 无法从 $CONFIGTX_FILE 读取 BatchTimeout。" >&2
  exit 2
fi

shutdown_network() {
  local log_file="$1"

  if run_logged \
    "清理 Fabric 网络" \
    "$log_file" \
    "$START_SCRIPT" "$DOWN_ATTR_COUNT" "$DOWN_ORG_COUNT" down; then
    CURRENT_NETWORK_UP=0
    return 0
  fi
  return 1
}

cleanup_on_exit() {
  local rc=$?
  trap - EXIT INT TERM

  if [ "$CURRENT_NETWORK_UP" -eq 1 ]; then
    echo "检测到网络仍在运行，执行退出清理……"
    "$START_SCRIPT" "$DOWN_ATTR_COUNT" "$DOWN_ORG_COUNT" down \
      > "$RAW_DIR/final_cleanup.log" 2>&1 || true
  fi
  if [ "$BATCH_TIMEOUT_CHANGED" -eq 1 ]; then
    set_batch_timeout "$ORIGINAL_BATCH_TIMEOUT" || true
  fi
  exit "$rc"
}

trap cleanup_on_exit EXIT INT TERM

extract_system_summary() {
  local source_log="$1"
  local output_file="$2"

  awk '
    /^================ EXPERIMENT_SUMMARY_BEGIN =+$/ {
      in_block = 1;
      is_target = 0;
      block = $0 ORS;
      next;
    }
    in_block {
      block = block $0 ORS;
      if ($0 == "EXPERIMENT=SystemLevelComparison") {
        is_target = 1;
      }
      if ($0 ~ /^================= EXPERIMENT_SUMMARY_END =+$/) {
        if (is_target) {
          printf "%s", block;
        }
        in_block = 0;
        is_target = 0;
        block = "";
      }
    }
  ' "$source_log" > "$output_file"

  local count
  count=$(grep -c '^EXPERIMENT=SystemLevelComparison$' "$output_file" || true)
  if [ "$count" -ne 1 ]; then
    echo "ERROR: 从 $source_log 提取到 $count 个 SystemLevelComparison 汇总块。" >&2
    return 1
  fi
}

extract_metric() {
  local source_file="$1"
  local key="$2"

  awk -F= -v key="$key" '
    $1 == key {
      value = $2;
      gsub(/^ +/, "", value);
      gsub(/ +$/, "", value);
      gsub(/\r/, "", value);
      print value;
      exit;
    }
  ' "$source_file"
}

require_metric() {
  local source_file="$1"
  local key="$2"
  local value

  value=$(extract_metric "$source_file" "$key")
  if [ -z "$value" ] || [ "$value" = "NA" ]; then
    echo "ERROR: $source_file 中缺少指标 $key。" >&2
    return 1
  fi
  printf '%s' "$value"
}

check_numeric_equal() {
  local actual="$1"
  local expected="$2"
  local label="$3"

  if ! awk -v a="$actual" -v e="$expected" \
    'BEGIN { d=a-e; if (d<0) d=-d; exit !(d <= 0.000001) }'; then
    echo "ERROR: $label 不匹配，期望 $expected，实际 $actual。" >&2
    return 1
  fi
}

check_stage_sum() {
  local label="$1"
  local total="$2"
  shift 2
  local values="$*"
  local difference

  difference=$(awk -v values="$values" -v total="$total" '
    BEGIN {
      count = split(values, item, " ");
      sum = 0;
      for (i = 1; i <= count; i++) sum += item[i];
      difference = sum - total;
      if (difference < 0) difference = -difference;
      printf "%.3f", difference;
    }
  ')

  if ! awk -v d="$difference" 'BEGIN { exit !(d <= 1.000) }'; then
    echo "ERROR: $label 的阶段和与总时间相差 $difference ms。" >&2
    return 1
  fi
}

validate_summary() {
  local summary_file="$1"
  local expected_attr_num="$2"
  local required_keys
  local key
  local actual_attr_num
  local actual_legal_space
  local actual_sigma
  local actual_affected_users
  local data_object_bytes
  local user_total
  local storage_total
  local retrieve_total

  required_keys="ATTR_NUM LEGAL_SPACE_SIZE TARGET_SIGMA AFFECTED_USERS DATA_OBJECT_BYTES USER_REGISTER_ZKGUARD_MS USER_REGISTER_POLYLOCK_KEYGEN_MS USER_REGISTER_SUPPORT_MS USER_REGISTER_TOTAL_MS DATA_STORAGE_POLICY_ENCODE_MS DATA_STORAGE_POLYLOCK_MS DATA_STORAGE_BLOCKCHAIN_MS DATA_STORAGE_TOTAL_MS DATA_RETRIEVE_PROOF_EXCHANGE_MS DATA_RETRIEVE_IPFS_GET_MS DATA_RETRIEVE_POLYLOCK_DECRYPT_MS DATA_RETRIEVE_TOTAL_MS POLICY_UPDATE_TOTAL_MS POLICY_UPDATE_OBSERVED_DELTA POLICY_UPDATE_DELTA_ADD POLICY_UPDATE_DELTA_RM ATTRIBUTE_UPDATE_TOTAL_MS"

  for key in $required_keys; do
    require_metric "$summary_file" "$key" > /dev/null || return 1
  done

  actual_attr_num=$(require_metric "$summary_file" "ATTR_NUM") || return 1
  actual_legal_space=$(require_metric "$summary_file" "LEGAL_SPACE_SIZE") || return 1
  actual_sigma=$(require_metric "$summary_file" "TARGET_SIGMA") || return 1
  actual_affected_users=$(require_metric "$summary_file" "AFFECTED_USERS") || return 1
  data_object_bytes=$(require_metric "$summary_file" "DATA_OBJECT_BYTES") || return 1

  check_numeric_equal "$actual_attr_num" "$expected_attr_num" "属性数量" || return 1
  check_numeric_equal "$actual_legal_space" "$((expected_attr_num * 10))" "合法属性空间规模" || return 1
  check_numeric_equal "$actual_sigma" "$FIXED_SIGMA" "策略松紧度" || return 1
  check_numeric_equal "$actual_affected_users" "$AFFECTED_USERS" "受影响用户数量" || return 1

  check_numeric_equal "$data_object_bytes" "$DATA_OBJECT_BYTES" "数据对象字节数" || return 1

  user_total=$(require_metric "$summary_file" "USER_REGISTER_TOTAL_MS") || return 1
  check_stage_sum \
    "用户注册" "$user_total" \
    "$(require_metric "$summary_file" "USER_REGISTER_ZKGUARD_MS")" \
    "$(require_metric "$summary_file" "USER_REGISTER_POLYLOCK_KEYGEN_MS")" \
    "$(require_metric "$summary_file" "USER_REGISTER_SUPPORT_MS")" || return 1

  storage_total=$(require_metric "$summary_file" "DATA_STORAGE_TOTAL_MS") || return 1
  check_stage_sum \
    "数据存储" "$storage_total" \
    "$(require_metric "$summary_file" "DATA_STORAGE_POLICY_ENCODE_MS")" \
    "$(require_metric "$summary_file" "DATA_STORAGE_POLYLOCK_MS")" \
    "$(require_metric "$summary_file" "DATA_STORAGE_BLOCKCHAIN_MS")" || return 1

  retrieve_total=$(require_metric "$summary_file" "DATA_RETRIEVE_TOTAL_MS") || return 1
  check_stage_sum \
    "数据获取" "$retrieve_total" \
    "$(require_metric "$summary_file" "DATA_RETRIEVE_PROOF_EXCHANGE_MS")" \
    "$(require_metric "$summary_file" "DATA_RETRIEVE_IPFS_GET_MS")" \
    "$(require_metric "$summary_file" "DATA_RETRIEVE_POLYLOCK_DECRYPT_MS")" || return 1
}

append_measurement() {
  local summary_file="$1"
  local attr_num="$2"
  local run_index="$3"
  local keys
  local values=()
  local key

  keys="LEGAL_SPACE_SIZE TARGET_SIGMA AFFECTED_USERS DATA_OBJECT_BYTES USER_REGISTER_ZKGUARD_MS USER_REGISTER_POLYLOCK_KEYGEN_MS USER_REGISTER_SUPPORT_MS USER_REGISTER_TOTAL_MS DATA_STORAGE_POLICY_ENCODE_MS DATA_STORAGE_POLYLOCK_MS DATA_STORAGE_BLOCKCHAIN_MS DATA_STORAGE_TOTAL_MS DATA_RETRIEVE_PROOF_EXCHANGE_MS DATA_RETRIEVE_IPFS_GET_MS DATA_RETRIEVE_POLYLOCK_DECRYPT_MS DATA_RETRIEVE_TOTAL_MS POLICY_UPDATE_TOTAL_MS POLICY_UPDATE_OBSERVED_DELTA POLICY_UPDATE_DELTA_ADD POLICY_UPDATE_DELTA_RM ATTRIBUTE_UPDATE_TOTAL_MS"

  for key in $keys; do
    values+=("$(require_metric "$summary_file" "$key")")
  done

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$attr_num" \
    "${values[0]}" "${values[1]}" "${values[2]}" "$run_index" \
    "${values[3]}" "${values[4]}" "${values[5]}" "${values[6]}" \
    "${values[7]}" "${values[8]}" "${values[9]}" "${values[10]}" \
    "${values[11]}" "${values[12]}" "${values[13]}" "${values[14]}" \
    "${values[15]}" "${values[16]}" "${values[17]}" "${values[18]}" \
    "${values[19]}" "${values[20]}" >> "$MEASUREMENTS"
}

append_summary() {
  local summary_file="$1"

  cat "$summary_file" >> "$ALL_AGGREGATE"
  printf '\n' >> "$ALL_AGGREGATE"
}

record_manifest() {
  local attr_num="$1"
  local run_index="$2"
  local status="$3"
  local failure_stage="$4"
  local duration_s="$5"
  local summary_file="$6"
  local test_log="$7"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$attr_num" "$FIXED_SIGMA" "$AFFECTED_USERS" "$run_index" \
    "$status" "$failure_stage" "$duration_s" "$summary_file" "$test_log" \
    >> "$MANIFEST"
}

run_one() {
  local attr_num="$1"
  local run_index="$2"
  local run_tag
  local prefix
  local down_log
  local up_log
  local test_log
  local summary_file

  printf -v run_tag '%02d' "$run_index"
  local sigma_tag=${FIXED_SIGMA//./p}
  local legal_space_size=$((attr_num * 10))
  prefix="N${attr_num}_sigma${sigma_tag}_R${AFFECTED_USERS}_run${run_tag}"
  down_log="$RAW_DIR/${prefix}_down.log"
  up_log="$RAW_DIR/${prefix}_up.log"
  test_log="$RAW_DIR/${prefix}_test.log"
  summary_file="$SUMMARY_DIR/${prefix}_summary.txt"

  LAST_FAILURE_STAGE=""
  LAST_SUMMARY_FILE="$summary_file"
  LAST_TEST_LOG="$test_log"

  echo
  echo "============================================================"
  echo "N=$attr_num | |S*|=$((attr_num * 10)) | sigma=$FIXED_SIGMA | R=$AFFECTED_USERS | run=$run_index/$REPEATS"
  echo "============================================================"

  if ! shutdown_network "$down_log"; then
    LAST_FAILURE_STAGE="down"
    return 1
  fi

  CURRENT_NETWORK_UP=1
  if ! run_logged \
    "启动 Fabric：N=$attr_num, org=$UP_ORG_COUNT, sigma=$FIXED_SIGMA" \
    "$up_log" \
    "$START_SCRIPT" "$attr_num" "$UP_ORG_COUNT" up "$FIXED_SIGMA" "$legal_space_size"; then
    LAST_FAILURE_STAGE="up"
    return 1
  fi

  if ! run_logged \
    "执行系统级测试：N=$attr_num, R=$AFFECTED_USERS" \
    "$test_log" \
    env RUN_LARGE_BENCH=0 "$TEST_SCRIPT" \
      --attr-num "$attr_num" \
      --legal-space-size "$legal_space_size" \
      --target-sigma "$FIXED_SIGMA" \
      --affected-users "$AFFECTED_USERS" \
      --data-object-file "$DATA_OBJECT_FILE"; then
    LAST_FAILURE_STAGE="test"
    return 1
  fi

  if ! extract_system_summary "$test_log" "$summary_file"; then
    LAST_FAILURE_STAGE="extract_summary"
    return 1
  fi

  if ! validate_summary "$summary_file" "$attr_num"; then
    LAST_FAILURE_STAGE="validate_summary"
    return 1
  fi

  append_summary "$summary_file"
  append_measurement "$summary_file" "$attr_num" "$run_index"
  echo "系统级实验汇总已保存: $summary_file"
  return 0
}

run_case_and_record() {
  local attr_num="$1"
  local run_index="$2"
  local start_s
  local end_s
  local duration_s

  start_s=$(date +%s)
  if run_one "$attr_num" "$run_index"; then
    end_s=$(date +%s)
    duration_s=$((end_s - start_s))
    record_manifest "$attr_num" "$run_index" \
      "OK" "" "$duration_s" "$LAST_SUMMARY_FILE" "$LAST_TEST_LOG"
  else
    end_s=$(date +%s)
    duration_s=$((end_s - start_s))
    record_manifest "$attr_num" "$run_index" \
      "FAILED" "$LAST_FAILURE_STAGE" "$duration_s" \
      "$LAST_SUMMARY_FILE" "$LAST_TEST_LOG"

    if "$START_SCRIPT" "$DOWN_ATTR_COUNT" "$DOWN_ORG_COUNT" down \
      > "$RAW_DIR/failed_run_cleanup_N${attr_num}_run${run_index}.log" 2>&1; then
      CURRENT_NETWORK_UP=0
    else
      CURRENT_NETWORK_UP=1
    fi

    if [ "$CONTINUE_ON_ERROR" != "1" ]; then
      echo "实验在失败处停止。设置 CONTINUE_ON_ERROR=1 可在失败后继续。" >&2
      return 1
    fi
  fi

  if [ "$COOLDOWN_SECONDS" -gt 0 ]; then
    sleep "$COOLDOWN_SECONDS"
  fi
}

echo "系统级端到端批量实验开始"
echo "每个参数点重复次数 : $REPEATS"
echo "结果目录           : $RESULT_ROOT"
echo "属性规模           : N={${ATTR_VALUES[*]}}"
echo "固定合法空间规模   : |S*|=10N"
echo "固定策略松紧度     : sigma=$FIXED_SIGMA"
echo "固定受影响用户数   : R=$AFFECTED_USERS"
echo "地学数据对象       : $DATA_OBJECT_FILE"
echo "对象字节数         : $DATA_OBJECT_BYTES"
echo "对象 SHA-256       : $DATA_OBJECT_SHA256"
echo "Fabric BatchTimeout: $EXPERIMENT_BATCH_TIMEOUT（实验结束后恢复为 $ORIGINAL_BATCH_TIMEOUT）"

set_batch_timeout "$EXPERIMENT_BATCH_TIMEOUT"
BATCH_TIMEOUT_CHANGED=1

for attr_num in "${ATTR_VALUES[@]}"; do
  for ((run_index = 1; run_index <= REPEATS; run_index++)); do
    run_case_and_record "$attr_num" "$run_index"
  done
done

if ! shutdown_network "$RAW_DIR/final_down.log"; then
  echo "ERROR: 实验已完成，但最终网络清理失败。" >&2
  exit 1
fi

set_batch_timeout "$ORIGINAL_BATCH_TIMEOUT"
BATCH_TIMEOUT_CHANGED=0

python3 "$SCRIPT_DIR/scripts/chapter05/prepare_system_comparison_plot_data.py" \
  --input-dir "$RESULT_ROOT"

echo
echo "全部实验完成。"
echo "全部摘要 : $ALL_AGGREGATE"
echo "逐轮 TSV : $MEASUREMENTS"
echo "运行清单 : $MANIFEST"
