#!/usr/bin/env bash

set -Eeuo pipefail

# AttributeUpdate 单变量批量实验：
#   A. N = 100, 200, 300, 400, 500, 600, 700, 800，固定 R = 100；
#   B. R = 1, 50, 100, 150, 200, 250, 300，固定 N = 400。
# 两组实验均固定 sigma = 0.5，合法属性空间规模由源码设置为 |S*| = 10N。
#
# 用法：
#   ./run_attribute_update_sweep.sh [每个参数点的重复次数]
#
# 示例：
#   ./run_attribute_update_sweep.sh 5
#   REPEATS=10 ./run_attribute_update_sweep.sh
#   SWEEP_MODE=n ./run_attribute_update_sweep.sh 5
#   SWEEP_MODE=r ./run_attribute_update_sweep.sh 5
#
# 可选环境变量：
#   RESULT_ROOT=/path/to/results  指定本次实验结果目录；
#   COOLDOWN_SECONDS=5            两轮之间的等待秒数；
#   CONTINUE_ON_ERROR=1           单轮失败后继续，默认遇错停止；
#   SWEEP_MODE=all|n|r            执行全部、仅 N 实验或仅 R 实验。

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
START_SCRIPT="$SCRIPT_DIR/start_fabric_zkguard.sh"
TEST_SCRIPT="$SCRIPT_DIR/test_ipfs_cluster.sh"

REPEATS="${1:-${REPEATS:-5}}"
COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-5}"
CONTINUE_ON_ERROR="${CONTINUE_ON_ERROR:-0}"
SWEEP_MODE="${SWEEP_MODE:-all}"

# 与现有手动流程一致：down 清理历史上可能存在的 4..25 号组织，
# 每次正式启动使用 4 个组织。
DOWN_ATTR_COUNT=1000
DOWN_ORG_COUNT=25
UP_ORG_COUNT=4
FIXED_SIGMA=0.5
DATA_OBJECT_BYTES=1

N_VALUES=(100 200 300 400 500 600 700 800)
N_SWEEP_FIXED_R=100

R_VALUES=(1 50 100 150 200 250 300)
R_SWEEP_FIXED_N=400

RUN_STAMP=$(date '+%Y%m%d_%H%M%S')
RESULT_ROOT="${RESULT_ROOT:-$SCRIPT_DIR/attribute_update_results/$RUN_STAMP}"
RAW_DIR="$RESULT_ROOT/raw_logs"
SUMMARY_DIR="$RESULT_ROOT/summaries"
N_AGGREGATE="$RESULT_ROOT/attribute_update_N_sweep.txt"
R_AGGREGATE="$RESULT_ROOT/attribute_update_R_sweep.txt"
ALL_AGGREGATE="$RESULT_ROOT/attribute_update_all_summaries.txt"
MEASUREMENTS="$RESULT_ROOT/attribute_update_measurements.tsv"
MANIFEST="$RESULT_ROOT/manifest.tsv"

CURRENT_NETWORK_UP=0
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
if [ "$SWEEP_MODE" != "all" ] && [ "$SWEEP_MODE" != "n" ] && [ "$SWEEP_MODE" != "r" ]; then
  echo "ERROR: SWEEP_MODE 只能取 all、n 或 r。" >&2
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
: > "$N_AGGREGATE"
: > "$R_AGGREGATE"
: > "$ALL_AGGREGATE"
printf 'sweep\tattr_num\taffected_users\tsigma\trun\tlocal_commit_ms\tchain_update_ms\tpolylock_keygen_ms\ttotal_ms\tprofile_space_load_diag_ms\tonline_wall_ms\tcold_wall_ms\tstage_sum_diff_ms\n' > "$MEASUREMENTS"
printf 'sweep\tattr_num\taffected_users\tsigma\trun\tstatus\tfailure_stage\tduration_s\tsummary_file\ttest_log\n' > "$MANIFEST"

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
  exit "$rc"
}

trap cleanup_on_exit EXIT INT TERM

extract_metric() {
  local source_log="$1"
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
  ' "$source_log"
}

require_metric() {
  local source_log="$1"
  local key="$2"
  local value

  value=$(extract_metric "$source_log" "$key")
  if [ -z "$value" ] || [ "$value" = "NA" ]; then
    echo "ERROR: $source_log 中缺少指标 $key。" >&2
    return 1
  fi
  printf '%s' "$value"
}

write_attribute_summary() {
  local source_log="$1"
  local output_file="$2"
  local sweep="$3"
  local attr_num="$4"
  local affected_users="$5"
  local run_index="$6"

  local local_ms
  local chain_ms
  local keygen_ms
  local total_ms
  local profile_load_ms
  local online_wall_ms
  local cold_wall_ms
  local stage_sum_ms
  local stage_diff_ms
  local wall_gap_ms

  local_ms=$(require_metric "$source_log" "LOCAL_COMMIT_REFRESH_MS") || return 1
  chain_ms=$(require_metric "$source_log" "CHAIN_ATTRIBUTE_UPDATE_MS") || return 1
  keygen_ms=$(require_metric "$source_log" "POLYLOCK_KEYGEN_TOTAL_MS") || return 1
  total_ms=$(require_metric "$source_log" "ATTRIBUTE_UPDATE_TOTAL_MS") || return 1
  profile_load_ms=$(require_metric "$source_log" "PROFILE_SPACE_LOAD_DIAG_MS") || return 1
  online_wall_ms=$(require_metric "$source_log" "ATTRIBUTE_UPDATE_WALL_EXCL_PROFILE_SPACE_MS") || return 1
  cold_wall_ms=$(require_metric "$source_log" "ATTRIBUTE_UPDATE_WALL_MS") || return 1

  stage_sum_ms=$(awk -v a="$local_ms" -v b="$chain_ms" -v c="$keygen_ms" \
    'BEGIN { printf "%.3f", a+b+c }')
  stage_diff_ms=$(awk -v s="$stage_sum_ms" -v t="$total_ms" \
    'BEGIN { d=s-t; if (d<0) d=-d; printf "%.3f", d }')
  wall_gap_ms=$(awk -v w="$online_wall_ms" -v t="$total_ms" \
    'BEGIN { printf "%.3f", w-t }')

  if ! awk -v d="$stage_diff_ms" 'BEGIN { exit !(d <= 0.010) }'; then
    echo "ERROR: 三阶段之和与 ATTRIBUTE_UPDATE_TOTAL_MS 相差 $stage_diff_ms ms。" >&2
    return 1
  fi

  {
    echo "================ EXPERIMENT_SUMMARY_BEGIN ================"
    echo "EXPERIMENT=AttributeUpdate"
    echo "SWEEP=$sweep"
    echo "RUN_INDEX=$run_index"
    echo "ATTR_NUM=$attr_num"
    echo "LEGAL_SPACE_SIZE=$((attr_num * 10))"
    echo "TARGET_SIGMA=$FIXED_SIGMA"
    echo "AFFECTED_USERS=$affected_users"
    echo "LOCAL_COMMIT_REFRESH_MS=$local_ms"
    echo "CHAIN_ATTRIBUTE_UPDATE_MS=$chain_ms"
    echo "POLYLOCK_KEYGEN_TOTAL_MS=$keygen_ms"
    echo "ATTRIBUTE_UPDATE_STAGE_SUM_MS=$stage_sum_ms"
    echo "ATTRIBUTE_UPDATE_TOTAL_MS=$total_ms"
    echo "ATTRIBUTE_UPDATE_SUM_DIFF_MS=$stage_diff_ms"
    echo "PROFILE_SPACE_LOAD_DIAG_MS=$profile_load_ms"
    echo "ATTRIBUTE_UPDATE_WALL_EXCL_PROFILE_SPACE_MS=$online_wall_ms"
    echo "ATTRIBUTE_UPDATE_WALL_GAP_MS=$wall_gap_ms"
    echo "ATTRIBUTE_UPDATE_COLD_WALL_MS=$cold_wall_ms"
    echo "================= EXPERIMENT_SUMMARY_END ================="
  } > "$output_file"
}

append_summary() {
  local summary_file="$1"
  local sweep_aggregate="$2"

  cat "$summary_file" >> "$sweep_aggregate"
  printf '\n' >> "$sweep_aggregate"
  cat "$summary_file" >> "$ALL_AGGREGATE"
  printf '\n' >> "$ALL_AGGREGATE"
}

append_measurement() {
  local summary_file="$1"
  local sweep="$2"
  local attr_num="$3"
  local affected_users="$4"
  local run_index="$5"

  local local_ms
  local chain_ms
  local keygen_ms
  local total_ms
  local profile_load_ms
  local online_wall_ms
  local cold_wall_ms
  local stage_diff_ms

  local_ms=$(extract_metric "$summary_file" "LOCAL_COMMIT_REFRESH_MS")
  chain_ms=$(extract_metric "$summary_file" "CHAIN_ATTRIBUTE_UPDATE_MS")
  keygen_ms=$(extract_metric "$summary_file" "POLYLOCK_KEYGEN_TOTAL_MS")
  total_ms=$(extract_metric "$summary_file" "ATTRIBUTE_UPDATE_TOTAL_MS")
  profile_load_ms=$(extract_metric "$summary_file" "PROFILE_SPACE_LOAD_DIAG_MS")
  online_wall_ms=$(extract_metric "$summary_file" "ATTRIBUTE_UPDATE_WALL_EXCL_PROFILE_SPACE_MS")
  cold_wall_ms=$(extract_metric "$summary_file" "ATTRIBUTE_UPDATE_COLD_WALL_MS")
  stage_diff_ms=$(extract_metric "$summary_file" "ATTRIBUTE_UPDATE_SUM_DIFF_MS")

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$sweep" "$attr_num" "$affected_users" "$FIXED_SIGMA" "$run_index" \
    "$local_ms" "$chain_ms" "$keygen_ms" "$total_ms" "$profile_load_ms" \
    "$online_wall_ms" "$cold_wall_ms" "$stage_diff_ms" >> "$MEASUREMENTS"
}

record_manifest() {
  local sweep="$1"
  local attr_num="$2"
  local affected_users="$3"
  local run_index="$4"
  local status="$5"
  local failure_stage="$6"
  local duration_s="$7"
  local summary_file="$8"
  local test_log="$9"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$sweep" "$attr_num" "$affected_users" "$FIXED_SIGMA" "$run_index" \
    "$status" "$failure_stage" "$duration_s" "$summary_file" "$test_log" >> "$MANIFEST"
}

run_one() {
  local sweep="$1"
  local attr_num="$2"
  local affected_users="$3"
  local run_index="$4"
  local sweep_aggregate="$5"
  local legal_space_size=$((attr_num * 10))

  local run_tag
  printf -v run_tag '%02d' "$run_index"
  local prefix="${sweep}_N${attr_num}_R${affected_users}_run${run_tag}"
  local down_log="$RAW_DIR/${prefix}_down.log"
  local up_log="$RAW_DIR/${prefix}_up.log"
  local test_log="$RAW_DIR/${prefix}_test.log"
  local summary_file="$SUMMARY_DIR/${prefix}_summary.txt"

  LAST_FAILURE_STAGE=""
  LAST_SUMMARY_FILE="$summary_file"
  LAST_TEST_LOG="$test_log"

  echo
  echo "============================================================"
  echo "Sweep=$sweep | N=$attr_num | R=$affected_users | sigma=$FIXED_SIGMA | run=$run_index/$REPEATS"
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
    "执行 AttributeUpdate 测试：N=$attr_num, R=$affected_users" \
    "$test_log" \
    env RUN_LARGE_BENCH=0 "$TEST_SCRIPT" \
      --attr-num "$attr_num" \
      --legal-space-size "$legal_space_size" \
      --target-sigma "$FIXED_SIGMA" \
      --affected-users "$affected_users" \
      --data-object-bytes "$DATA_OBJECT_BYTES"; then
    LAST_FAILURE_STAGE="test"
    return 1
  fi

  if ! write_attribute_summary \
    "$test_log" "$summary_file" "$sweep" "$attr_num" "$affected_users" "$run_index"; then
    LAST_FAILURE_STAGE="extract_summary"
    return 1
  fi

  append_summary "$summary_file" "$sweep_aggregate"
  append_measurement "$summary_file" "$sweep" "$attr_num" "$affected_users" "$run_index"
  echo "AttributeUpdate 汇总已保存: $summary_file"
  return 0
}

run_case_and_record() {
  local sweep="$1"
  local attr_num="$2"
  local affected_users="$3"
  local run_index="$4"
  local sweep_aggregate="$5"
  local start_s
  local end_s
  local duration_s

  start_s=$(date +%s)
  if run_one "$sweep" "$attr_num" "$affected_users" "$run_index" "$sweep_aggregate"; then
    end_s=$(date +%s)
    duration_s=$((end_s - start_s))
    record_manifest "$sweep" "$attr_num" "$affected_users" "$run_index" \
      "OK" "" "$duration_s" "$LAST_SUMMARY_FILE" "$LAST_TEST_LOG"
  else
    end_s=$(date +%s)
    duration_s=$((end_s - start_s))
    record_manifest "$sweep" "$attr_num" "$affected_users" "$run_index" \
      "FAILED" "$LAST_FAILURE_STAGE" "$duration_s" "$LAST_SUMMARY_FILE" "$LAST_TEST_LOG"

    if "$START_SCRIPT" "$DOWN_ATTR_COUNT" "$DOWN_ORG_COUNT" down \
      > "$RAW_DIR/failed_run_cleanup_${sweep}_N${attr_num}_R${affected_users}_run${run_index}.log" 2>&1; then
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

echo "AttributeUpdate 批量实验开始"
echo "每个参数点重复次数 : $REPEATS"
echo "实验模式           : $SWEEP_MODE"
echo "结果目录           : $RESULT_ROOT"
echo "固定 sigma         : $FIXED_SIGMA"
echo "属性规模实验       : N={${N_VALUES[*]}}, R=$N_SWEEP_FIXED_R"
echo "受影响用户实验     : N=$R_SWEEP_FIXED_N, R={${R_VALUES[*]}}"

if [ "$SWEEP_MODE" = "all" ] || [ "$SWEEP_MODE" = "n" ]; then
  for attr_num in "${N_VALUES[@]}"; do
    for ((run_index = 1; run_index <= REPEATS; run_index++)); do
      run_case_and_record \
        "N" "$attr_num" "$N_SWEEP_FIXED_R" "$run_index" "$N_AGGREGATE"
    done
  done
fi

if [ "$SWEEP_MODE" = "all" ] || [ "$SWEEP_MODE" = "r" ]; then
  for affected_users in "${R_VALUES[@]}"; do
    for ((run_index = 1; run_index <= REPEATS; run_index++)); do
      run_case_and_record \
        "R" "$R_SWEEP_FIXED_N" "$affected_users" "$run_index" "$R_AGGREGATE"
    done
  done
fi

if ! shutdown_network "$RAW_DIR/final_down.log"; then
  echo "ERROR: 实验已完成，但最终网络清理失败。" >&2
  exit 1
fi

python3 "$SCRIPT_DIR/scripts/chapter05/prepare_attribute_update_plot_data.py" \
  --input-dir "$RESULT_ROOT"

echo
echo "全部实验完成。"
echo "N 实验汇总    : $N_AGGREGATE"
echo "R 实验汇总    : $R_AGGREGATE"
echo "全部汇总      : $ALL_AGGREGATE"
echo "逐轮 TSV      : $MEASUREMENTS"
echo "运行清单      : $MANIFEST"
