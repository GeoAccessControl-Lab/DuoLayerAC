#!/usr/bin/env python3

import argparse
import csv
import math
import statistics
from pathlib import Path


def percentile(values, q):
    ordered = sorted(values)
    position = max(0, math.ceil(q * len(ordered)) - 1)
    return ordered[min(position, len(ordered) - 1)]


def describe(values):
    return {
        "n": len(values),
        "mean_ms": statistics.fmean(values),
        "std_ms": statistics.stdev(values) if len(values) > 1 else 0.0,
        "p50_ms": percentile(values, 0.50),
        "p95_ms": percentile(values, 0.95),
        "p99_ms": percentile(values, 0.99),
    }


def read_column(path, column):
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    return [float(row[column]) for row in rows]


def write_rows(path, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    component_rows = []
    primary = {}
    for model in ("LR", "DNN"):
        path = args.input_dir / f"bfr_{model.lower()}_raw.csv"
        for component, column in (
            ("feature encoding", "feature_encode_ms"),
            ("model inference", "model_inference_ms"),
            ("request decision", "detection_total_ms"),
        ):
            result = describe(read_column(path, column))
            component_rows.append({"mechanism": f"BFR-Det-{model}", "component": component, **result})
            if component == "request decision":
                primary[model] = result

    zk_path = args.input_dir / "zkguard_raw.csv"
    for component, column in (
        ("complete permission decision", "provider_permission_decision_ms"),
        ("proof bundle read", "proof_bundle_read_ms"),
        ("chaincode Groth16 verification", "chaincode_verify_ms"),
        ("chain authorization decision", "chain_decision_ms"),
        ("client verification path", "verify_total_ms"),
    ):
        result = describe(read_column(zk_path, column))
        component_rows.append({"mechanism": "zk-Guard", "component": component, **result})
        if component == "complete permission decision":
            primary["zk-Guard"] = result

    write_rows(args.output_dir / "component_summary.csv", component_rows)

    comparison_rows = []
    zk_mean = primary["zk-Guard"]["mean_ms"]
    for model in ("LR", "DNN"):
        value = primary[model]
        comparison_rows.append({
            "mechanism": f"BFR-Det-{model}",
            **value,
            "relative_speedup_vs_zkguard": zk_mean / value["mean_ms"],
            "break_even_rejection_rate_percent": 100.0 * value["mean_ms"] / zk_mean,
        })
    comparison_rows.append({
        "mechanism": "zk-Guard",
        **primary["zk-Guard"],
        "relative_speedup_vs_zkguard": 1.0,
        "break_even_rejection_rate_percent": "",
    })
    write_rows(args.output_dir / "comparison_summary.csv", comparison_rows)

    print("\nPrimary per-request comparison")
    print(f"{'Mechanism':<16} {'Mean±Std (ms)':>24} {'P50':>10} {'P95':>10} {'P99':>10} {'Ratio':>12} {'Break-even':>14}")
    for row in comparison_rows:
        ratio = f"{float(row['relative_speedup_vs_zkguard']):.1f}x"
        threshold = row["break_even_rejection_rate_percent"]
        threshold_text = "--" if threshold == "" else f"{float(threshold):.3f}%"
        print(
            f"{row['mechanism']:<16} "
            f"{float(row['mean_ms']):10.6f}±{float(row['std_ms']):.6f} "
            f"{float(row['p50_ms']):10.6f} {float(row['p95_ms']):10.6f} "
            f"{float(row['p99_ms']):10.6f} {ratio:>12} {threshold_text:>14}"
        )
    print(f"\ncomponent_summary={args.output_dir / 'component_summary.csv'}")
    print(f"comparison_summary={args.output_dir / 'comparison_summary.csv'}")


if __name__ == "__main__":
    main()
