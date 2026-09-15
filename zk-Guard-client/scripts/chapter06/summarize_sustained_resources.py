#!/usr/bin/env python3
"""Summarize fixed-rate BFR-Det and zk-Guard resource trials."""

from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from pathlib import Path


METHODS = {
    "bfr_lr": ("BFR-Det (LR)", "detection_total_ms"),
    "bfr_dnn": ("BFR-Det (DNN)", "detection_total_ms"),
    "zkguard": ("zk-Guard complete decision", "complete_decision_ms"),
}


def mean_std(values: list[float]) -> tuple[float, float]:
    return statistics.mean(values), statistics.stdev(values) if len(values) > 1 else 0.0


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))
    return ordered[index]


def summary_value(path: Path, key: str) -> float:
    prefix = key + "="
    for line in path.read_text().splitlines():
        if line.startswith(prefix):
            return float(line[len(prefix):])
    raise ValueError(f"{path}: missing {key}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--requests-per-trial", type=int, required=True)
    args = parser.parse_args()

    rows = []
    components = []
    for prefix, (label, latency_field) in METHODS.items():
        resource_files = sorted(args.input_dir.glob(f"{prefix}_trial*_resource.json"))
        timing_files = sorted(args.input_dir.glob(f"{prefix}_trial*_timing.csv"))
        if not resource_files and not timing_files:
            continue
        if not resource_files or len(resource_files) != len(timing_files):
            raise SystemExit(f"incomplete trial set for {prefix}")
        resources = [json.loads(path.read_text()) for path in resource_files]
        command_files = sorted(args.input_dir.glob(f"{prefix}_trial*_command.txt"))
        if len(command_files) != len(resource_files):
            raise SystemExit(f"incomplete command summaries for {prefix}")
        timings = []
        mtp = []
        chain = []
        for path in timing_files:
            with path.open(newline="") as handle:
                trial_rows = list(csv.DictReader(handle))
            if len(trial_rows) != args.requests_per_trial:
                raise SystemExit(f"{path}: expected {args.requests_per_trial} rows, got {len(trial_rows)}")
            if prefix == "zkguard" and any(row["allowed"].lower() != "true" for row in trial_rows):
                raise SystemExit(f"{path}: an authorization decision failed")
            timings.extend(float(row[latency_field]) for row in trial_rows)
            if prefix == "zkguard":
                mtp.extend(float(row["mtp_verify_ms"]) for row in trial_rows)
                chain.extend(float(row["chain_decision_ms"]) for row in trial_rows)

        latency_mean, latency_std = mean_std(timings)
        record = {
            "method": label,
            "trials": len(resource_files),
            "requests_per_trial": args.requests_per_trial,
            "total_observations": len(timings),
            "request_rate_per_second": resources[0]["rate_per_second"],
            "decision_mean_ms": latency_mean,
            "decision_std_ms": latency_std,
            "decision_p50_ms": percentile(timings, 0.50),
            "decision_p95_ms": percentile(timings, 0.95),
        }
        for field in (
            "cpu_ms_per_request",
            "equivalent_single_core_cpu_pct",
            "resident_increment_mb",
            "active_peak_increment_mb",
            "service_peak_increment_mb",
            "active_peak_memory_mb",
        ):
            mean, std = mean_std([float(resource[field]) for resource in resources])
            record[f"{field}_mean"] = mean
            record[f"{field}_std"] = std
        if prefix.startswith("bfr_"):
            process_cpu = [summary_value(path, "PROCESS_CPU_MS_PER_REQUEST") for path in command_files]
            process_cpu_mean, process_cpu_std = mean_std(process_cpu)
            record["cpu_ms_per_request_mean"] = process_cpu_mean
            record["cpu_ms_per_request_std"] = process_cpu_std
            batch_cpu = [summary_value(path, "MEASURED_PROCESS_CPU_MS") for path in command_files]
            batch_wall = [summary_value(path, "BATCH_WALL_MS") for path in command_files]
            core_pct = [cpu / wall * 100.0 for cpu, wall in zip(batch_cpu, batch_wall)]
            core_mean, core_std = mean_std(core_pct)
            record["equivalent_single_core_cpu_pct_mean"] = core_mean
            record["equivalent_single_core_cpu_pct_std"] = core_std
        rows.append(record)
        if prefix == "zkguard":
            for component, values in (("MTP verification", mtp), ("chain authorization", chain)):
                mean, std = mean_std(values)
                components.append(
                    {
                        "component": component,
                        "mean_ms": mean,
                        "std_ms": std,
                        "p50_ms": percentile(values, 0.50),
                        "p95_ms": percentile(values, 0.95),
                    }
                )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    component_path = args.output.with_name("zkguard_component_summary.csv")
    with component_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(components[0]))
        writer.writeheader()
        writer.writerows(components)

    print("Sustained lightweight comparison")
    print("  method                     latency(ms)       CPU(ms/req)      CPU(core %)   resident(MB)   active peak(MB)")
    for row in rows:
        print(
            f"  {row['method']:<26} "
            f"{row['decision_mean_ms']:.6f}±{row['decision_std_ms']:.6f}  "
            f"{row['cpu_ms_per_request_mean']:.6f}±{row['cpu_ms_per_request_std']:.6f}  "
            f"{row['equivalent_single_core_cpu_pct_mean']:.3f}±{row['equivalent_single_core_cpu_pct_std']:.3f}  "
            f"{row['resident_increment_mb_mean']:.3f}±{row['resident_increment_mb_std']:.3f}  "
            f"{row['active_peak_increment_mb_mean']:.3f}±{row['active_peak_increment_mb_std']:.3f}"
        )
    print(f"SUMMARY_CSV={args.output}")
    print(f"COMPONENT_CSV={component_path}")


if __name__ == "__main__":
    main()
