#!/usr/bin/env python3
"""Build the Chapter 5 policy-update table and heat-map CSV files."""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path


STAGES = (
    ("Conf", "MCONF_GENERATE_MS"),
    ("Ver", "RESOLVE_ROOT_VERSIONS_MS"),
    ("Lock", "LOCK_REFRESH_MS"),
    ("Obj", "OBJECT_BUILD_MS"),
    ("IPFS", "IPFS_ADD_LOCK_ROOT_MS"),
    ("BC", "BLOCKCHAIN_REGISTER_MS"),
)


def parse_summary(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text().splitlines():
        if "=" in raw:
            key, value = raw.split("=", 1)
            values[key.strip()] = value.strip()
    if values.get("EXPERIMENT") != "PolicyUpdate":
        raise RuntimeError(f"not a PolicyUpdate summary: {path}")
    values["Sweep"] = "AttrNum" if path.name.startswith("attr_") else "Sigma"
    values["Source"] = str(path)
    return values


def mean_std(values: list[float]) -> tuple[float, float]:
    return statistics.fmean(values), statistics.stdev(values) if len(values) > 1 else 0.0


def write(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    output_dir = args.output_dir or args.input_dir / "plot_data"

    summaries = [parse_summary(path) for path in sorted((args.input_dir / "summaries").glob("*_summary.txt"))]
    if not summaries:
        raise RuntimeError(f"no policy summaries under {args.input_dir / 'summaries'}")

    groups: dict[tuple[str, int, float], list[dict[str, str]]] = defaultdict(list)
    for row in summaries:
        denominator = max(int(row["OLD_BUCKET_COUNT"]), int(row["NEW_BUCKET_COUNT"]))
        if denominator <= 0:
            raise RuntimeError(f"invalid bucket denominator: {row}")
        corrected_delta = int(row["AFFECTED_BUCKETS"]) / denominator
        if corrected_delta > 1.0 + 1e-12:
            raise RuntimeError(f"affected buckets exceed the union denominator: {row}")
        row["OBSERVED_DELTA_REPORTED"] = row["OBSERVED_DELTA"]
        row["OBSERVED_DELTA"] = f"{corrected_delta:.12f}"
        key = (row["Sweep"], int(row["ATTR_NUM"]), float(row["TARGET_SIGMA"]))
        groups[key].append(row)

    table: list[dict[str, str]] = []
    heatmap: list[dict[str, str]] = []
    for (sweep, attr_num, sigma), samples in sorted(groups.items(), key=lambda item: (item[0][0], item[0][1], item[0][2])):
        variable = str(attr_num) if sweep == "AttrNum" else f"{sigma:g}"
        item = {
            "Sweep": sweep,
            "Variable": variable,
            "AttrNum": str(attr_num),
            "LegalSpaceSize": samples[0]["LEGAL_SPACE_SIZE"],
            "TargetSigma": f"{sigma:g}",
            "Runs": str(len(samples)),
        }
        scalar_fields = (
            "DELTA_ADD", "DELTA_RM", "OBSERVED_DELTA", "OBSERVED_DELTA_REPORTED", "MCONF_GZIP_BYTES",
            "LOCK_CT_BYTES", "AFFECTED_BUCKETS", "OLD_BUCKET_COUNT", "NEW_BUCKET_COUNT",
            "POLICY_UPDATE_TOTAL_MS",
        ) + tuple(field for _, field in STAGES)
        for field in scalar_fields:
            mean, std = mean_std([float(sample[field]) for sample in samples])
            item[f"{field}_MEAN"] = f"{mean:.6f}"
            item[f"{field}_STD"] = f"{std:.6f}"
        item["MCONF_KB_MEAN"] = f"{float(item['MCONF_GZIP_BYTES_MEAN']) / 1024.0:.6f}"
        item["LOCK_MB_MEAN"] = f"{float(item['LOCK_CT_BYTES_MEAN']) / (1024.0 * 1024.0):.6f}"
        table.append(item)

        total = float(item["POLICY_UPDATE_TOTAL_MS_MEAN"])
        heat = {
            "Sweep": sweep,
            "Variable": variable,
            "AttrNum": str(attr_num),
            "TargetSigma": f"{sigma:g}",
        }
        for label, field in STAGES:
            heat[f"{label}Percent"] = f"{100.0 * float(item[f'{field}_MEAN']) / total:.6f}"
        heatmap.append(heat)

    table_csv = output_dir / "policy_update_breakdown_table.csv"
    heatmap_csv = output_dir / "policy_update_runtime_heatmap.csv"
    write(table_csv, table)
    write(heatmap_csv, heatmap)

    print("\nPolicy-update paper table (all six stages, ms)")
    print(
        f"{'Sweep':>8} {'x':>7} {'add/rm':>15} {'delta':>8} {'MconfKB':>8} {'LockMB':>8} "
        f"{'TConf':>9} {'TVer':>9} {'TLock':>9} {'TObj':>9} {'TIPFS':>9} {'TBC':>9} {'Total':>10}"
    )
    for row in table:
        add_rm = f"{float(row['DELTA_ADD_MEAN']):.1f}/{float(row['DELTA_RM_MEAN']):.1f}"
        print(
            f"{row['Sweep']:>8} {row['Variable']:>7} {add_rm:>15} "
            f"{float(row['OBSERVED_DELTA_MEAN']):>8.4f} {float(row['MCONF_KB_MEAN']):>8.3f} "
            f"{float(row['LOCK_MB_MEAN']):>8.3f} "
            f"{float(row['MCONF_GENERATE_MS_MEAN']):>9.3f} "
            f"{float(row['RESOLVE_ROOT_VERSIONS_MS_MEAN']):>9.3f} "
            f"{float(row['LOCK_REFRESH_MS_MEAN']):>9.3f} "
            f"{float(row['OBJECT_BUILD_MS_MEAN']):>9.3f} "
            f"{float(row['IPFS_ADD_LOCK_ROOT_MS_MEAN']):>9.3f} "
            f"{float(row['BLOCKCHAIN_REGISTER_MS_MEAN']):>9.3f} "
            f"{float(row['POLICY_UPDATE_TOTAL_MS_MEAN']):>10.3f}"
        )
    print("\nPolicy-update runtime composition (%)")
    print(
        f"{'Sweep':>8} {'x':>7} {'Conf':>9} {'Ver':>9} {'Lock':>9} "
        f"{'Obj':>9} {'IPFS':>9} {'BC':>9} {'Sum':>9}"
    )
    for row in heatmap:
        values = [float(row[f"{label}Percent"]) for label, _ in STAGES]
        print(
            f"{row['Sweep']:>8} {row['Variable']:>7} "
            + " ".join(f"{value:>9.3f}" for value in values)
            + f" {sum(values):>9.3f}"
        )
    print(f"\nTable CSV:   {table_csv}")
    print(f"Heat-map CSV: {heatmap_csv}")


if __name__ == "__main__":
    main()
