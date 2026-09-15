#!/usr/bin/env bash

set -Eeuo pipefail

# PolicyUpdate 单变量批量实验：
#   A. N = 100, 200, 400, 800，固定 sigma = 0.5；
#   B. sigma = 0.1, 0.2, 0.4, 0.8，固定 N = 400。
#
# 用法：
#   ./run_policy_update_sweep.sh [每个参数点的重复次数]
#
# 示例：
#   ./run_policy_update_sweep.sh 5
#   REPEATS=10 ./run_policy_update_sweep.sh
#
# 可选环境变量：
#   RESULT_ROOT=/path/to/results  指定本次实验结果目录；
#   COOLDOWN_SECONDS=5            两轮之间的等待秒数；
#   CONTINUE_ON_ERROR=1           单轮失败后继续后续参数点，默认遇错停止。

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
START_SCRIPT="$SCRIPT_DIR/start_fabric_zkguard.sh"
TEST_SCRIPT="$SCRIPT_DIR/test_ipfs_cluster.sh"

REPEATS="${1:-${REPEATS:-5}}"
COOLDOWN_SECONDS="${COOLDOWN_SECONDS:-5}"
CONTINUE_ON_ERROR="${CONTINUE_ON_ERROR:-0}"

# 与手动命令保持一致：down 清理历史上可能存在的 4..25 号组织，
# 每次正式启动只使用 4 个组织。
DOWN_ATTR_COUNT=1000
DOWN_ORG_COUNT=25
UP_ORG_COUNT=4
AFFECTED_USERS=1
DATA_OBJECT_BYTES=1

ATTR_VALUES=(100 200 400 800)
ATTR_FIXED_SIGMA=0.5
SIGMA_VALUES=(0.1 0.2 0.4 0.8)
SIGMA_FIXED_ATTR=400

RUN_STAMP=$(date '+%Y%m%d_%H%M%S')
RESULT_ROOT="${RESULT_ROOT:-$SCRIPT_DIR/policy_update_results/$RUN_STAMP}"
RAW_DIR="$RESULT_ROOT/raw_logs"
SUMMARY_DIR="$RESULT_ROOT/summaries"
ATTR_AGGREGATE="$RESULT_ROOT/policy_update_attr_sweep.txt"
SIGMA_AGGREGATE="$RESULT_ROOT/policy_update_sigma_sweep.txt"
ALL_AGGREGATE="$RESULT_ROOT/policy_update_all_summaries.txt"
MANIFEST="$RESULT_ROOT/manifest.tsv"

CURRENT_NETWORK_UP=0
LAST_FAILURE_STAGE=""
LAST_SUMMARY_FILE=""
LAST_TEST_LOG=""

usage_error() {
  echo "ERROR: 重复次数必须是正整数，当前值为: $REPEATS" >&2
  exit 2
}

if ! [[ "$REPEATS" =~ ^[1-9][0-9]*$ ]]; then
  usage_error
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
: > "$ATTR_AGGREGATE"
: > "$SIGMA_AGGREGATE"
: > "$ALL_AGGREGATE"
printf 'sweep\tattr_num\tsigma\trun\tstatus\tfailure_stage\tduration_s\tsummary_file\ttest_log\n' > "$MANIFEST"

run_logged() {
  local label="$1"
  local log_file="$2"
  shift 2

  echo "[$(date '+%F %T')] $label"
  if "$@" > "$log_file" 2>&1; then
    return 0
  fi

  echo "ERROR: $label 失败，日志: $log_file" >&2
  tail -n 40 "$log_file" >&2 || true
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

# test_ipfs_cluster.sh 中还有 AttributeUpdate 总结块。这里只提取
# EXPERIMENT=PolicyUpdate 所在的完整 EXPERIMENT_SUMMARY 区间。
extract_policy_update_summary() {
  local source_log="$1"
  local output_file="$2"

  awk '
    /^================ EXPERIMENT_SUMMARY_BEGIN =+$/ {
      in_block = 1;
      is_policy = 0;
      block = $0 ORS;
      next;
    }
    in_block {
      block = block $0 ORS;
      if ($0 == "EXPERIMENT=PolicyUpdate") {
        is_policy = 1;
      }
      if ($0 ~ /^================= EXPERIMENT_SUMMARY_END =+$/) {
        if (is_policy) {
          printf "%s", block;
        }
        in_block = 0;
        is_policy = 0;
        block = "";
      }
    }
  ' "$source_log" > "$output_file"

  local count
  count=$(grep -c '^EXPERIMENT=PolicyUpdate$' "$output_file" || true)
  if [ "$count" -ne 1 ]; then
    echo "ERROR: 从 $source_log 提取到 $count 个 PolicyUpdate 汇总块。" >&2
    return 1
  fi
}

append_summary() {
  local summary_file="$1"
  local sweep_aggregate="$2"

  cat "$summary_file" >> "$sweep_aggregate"
  printf '\n' >> "$sweep_aggregate"
  cat "$summary_file" >> "$ALL_AGGREGATE"
  printf '\n' >> "$ALL_AGGREGATE"
}

record_manifest() {
  local sweep="$1"
  local attr_num="$2"
  local sigma="$3"
  local run_index="$4"
  local status="$5"
  local failure_stage="$6"
  local duration_s="$7"
  local summary_file="$8"
  local test_log="$9"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$sweep" "$attr_num" "$sigma" "$run_index" "$status" \
    "$failure_stage" "$duration_s" "$summary_file" "$test_log" >> "$MANIFEST"
}

run_one() {
  local sweep="$1"
  local attr_num="$2"
  local sigma="$3"
  local run_index="$4"
  local sweep_aggregate="$5"
  local legal_space_size=$((attr_num * 10))

  local sigma_tag=${sigma//./p}
  local run_tag
  printf -v run_tag '%02d' "$run_index"
  local prefix="${sweep}_N${attr_num}_sigma${sigma_tag}_run${run_tag}"
  local down_log="$RAW_DIR/${prefix}_down.log"
  local up_log="$RAW_DIR/${prefix}_up.log"
  local test_log="$RAW_DIR/${prefix}_test.log"
  local summary_file="$SUMMARY_DIR/${prefix}_summary.txt"

  LAST_FAILURE_STAGE=""
  LAST_SUMMARY_FILE="$summary_file"
  LAST_TEST_LOG="$test_log"

  echo
  echo "============================================================"
  echo "Sweep=$sweep | N=$attr_num | sigma=$sigma | run=$run_index/$REPEATS"
  echo "============================================================"

  if ! shutdown_network "$down_log"; then
    LAST_FAILURE_STAGE="down"
    return 1
  fi

  # 从此处开始，即使 up 只完成了一部分，退出 trap 也会尝试清理。
  CURRENT_NETWORK_UP=1
  if ! run_logged \
    "启动 Fabric：N=$attr_num, org=$UP_ORG_COUNT, sigma=$sigma" \
    "$up_log" \
    "$START_SCRIPT" "$attr_num" "$UP_ORG_COUNT" up "$sigma" "$legal_space_size"; then
    LAST_FAILURE_STAGE="up"
    return 1
  fi

  if ! run_logged \
    "执行 test_ipfs_cluster.sh" \
    "$test_log" \
    env RUN_LARGE_BENCH=0 "$TEST_SCRIPT" \
      --attr-num "$attr_num" \
      --legal-space-size "$legal_space_size" \
      --target-sigma "$sigma" \
      --affected-users "$AFFECTED_USERS" \
      --data-object-bytes "$DATA_OBJECT_BYTES"; then
    LAST_FAILURE_STAGE="test"
    return 1
  fi

  if ! extract_policy_update_summary "$test_log" "$summary_file"; then
    LAST_FAILURE_STAGE="extract_summary"
    return 1
  fi

  append_summary "$summary_file" "$sweep_aggregate"
  echo "PolicyUpdate 汇总已保存: $summary_file"
  return 0
}

run_case_and_record() {
  local sweep="$1"
  local attr_num="$2"
  local sigma="$3"
  local run_index="$4"
  local sweep_aggregate="$5"
  local start_s
  local end_s
  local duration_s

  start_s=$(date +%s)
  if run_one "$sweep" "$attr_num" "$sigma" "$run_index" "$sweep_aggregate"; then
    end_s=$(date +%s)
    duration_s=$((end_s - start_s))
    record_manifest "$sweep" "$attr_num" "$sigma" "$run_index" \
      "OK" "" "$duration_s" "$LAST_SUMMARY_FILE" "$LAST_TEST_LOG"
  else
    end_s=$(date +%s)
    duration_s=$((end_s - start_s))
    record_manifest "$sweep" "$attr_num" "$sigma" "$run_index" \
      "FAILED" "$LAST_FAILURE_STAGE" "$duration_s" "$LAST_SUMMARY_FILE" "$LAST_TEST_LOG"

    # 失败后立即清理，避免污染下一轮。
    if "$START_SCRIPT" "$DOWN_ATTR_COUNT" "$DOWN_ORG_COUNT" down \
      > "$RAW_DIR/failed_run_cleanup_${sweep}_N${attr_num}_sigma${sigma}_run${run_index}.log" 2>&1; then
      CURRENT_NETWORK_UP=0
    else
      # 保持为 1，使退出 trap 再尝试清理一次。
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

echo "PolicyUpdate 批量实验开始"
echo "每个参数点重复次数 : $REPEATS"
echo "结果目录           : $RESULT_ROOT"
echo "属性规模实验       : N={${ATTR_VALUES[*]}}, sigma=$ATTR_FIXED_SIGMA"
echo "松紧度实验         : N=$SIGMA_FIXED_ATTR, sigma={${SIGMA_VALUES[*]}}"

for attr_num in "${ATTR_VALUES[@]}"; do
  for ((run_index = 1; run_index <= REPEATS; run_index++)); do
    run_case_and_record \
      "attr" "$attr_num" "$ATTR_FIXED_SIGMA" "$run_index" "$ATTR_AGGREGATE"
  done
done

for sigma in "${SIGMA_VALUES[@]}"; do
  for ((run_index = 1; run_index <= REPEATS; run_index++)); do
    run_case_and_record \
      "sigma" "$SIGMA_FIXED_ATTR" "$sigma" "$run_index" "$SIGMA_AGGREGATE"
  done
done

if ! shutdown_network "$RAW_DIR/final_down.log"; then
  echo "ERROR: 实验已完成，但最终网络清理失败。" >&2
  exit 1
fi

python3 "$SCRIPT_DIR/scripts/chapter05/prepare_policy_update_plot_data.py" \
  --input-dir "$RESULT_ROOT"

echo
echo "全部实验完成。"
echo "属性规模汇总 : $ATTR_AGGREGATE"
echo "松紧度汇总   : $SIGMA_AGGREGATE"
echo "全部汇总     : $ALL_AGGREGATE"
echo "运行清单     : $MANIFEST"
