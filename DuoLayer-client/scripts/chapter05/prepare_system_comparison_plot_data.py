#!/usr/bin/env python3
"""Aggregate PolyLock rows for the five Chapter 5 system-comparison panels."""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path


TOTALS = {
    "UserRegister": "user_register_total_ms",
    "DataStorage": "data_storage_total_ms",
    "DataRetrieve": "data_retrieve_total_ms",
    "PolicyUpdate": "policy_update_total_ms",
    "AttributeUpdate": "attribute_update_total_ms",
}


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
    source = args.input_dir / "system_level_measurements.tsv"
    output_dir = args.output_dir or args.input_dir / "plot_data"

    with source.open(newline="") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))
    if not rows:
        raise RuntimeError(f"no system measurements in {source}")

    groups: dict[int, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[int(row["attr_num"])].append(row)

    wide: list[dict[str, str]] = []
    long: list[dict[str, str]] = []
    for attr_num, samples in sorted(groups.items()):
        item = {
            "Scheme": "PolyLock+zk-Guard",
            "AttrNum": str(attr_num),
            "LegalSpaceSize": samples[0]["legal_space_size"],
            "TargetSigma": samples[0]["sigma"],
            "AffectedUsers": samples[0]["affected_users"],
            "DataObjectBytes": samples[0]["data_object_bytes"],
            "Runs": str(len(samples)),
        }
        for phase, column in TOTALS.items():
            mean, std = mean_std([float(row[column]) for row in samples])
            item[f"{phase}MSMean"] = f"{mean:.6f}"
            item[f"{phase}MSStd"] = f"{std:.6f}"
            long.append({
                "Scheme": "PolyLock+zk-Guard",
                "AttrNum": str(attr_num),
                "Phase": phase,
                "MeanMS": f"{mean:.6f}",
                "StdMS": f"{std:.6f}",
                "Runs": str(len(samples)),
            })
        wide.append(item)

    wide_csv = output_dir / "system_comparison_polylock_wide.csv"
    long_csv = output_dir / "system_comparison_polylock_long.csv"
    write(wide_csv, wide)
    write(long_csv, long)

    print("\nSystem-level PolyLock results")
    print(f"{'n':>6} " + " ".join(f"{phase:>18}" for phase in TOTALS))
    for row in wide:
        cells = [
            f"{float(row[f'{phase}MSMean']) / 1000.0:.3f}±{float(row[f'{phase}MSStd']) / 1000.0:.3f}s"
            for phase in TOTALS
        ]
        print(f"{row['AttrNum']:>6} " + " ".join(f"{cell:>18}" for cell in cells))
    print(f"\nWide CSV: {wide_csv}")
    print(f"Long CSV: {long_csv}")


if __name__ == "__main__":
    main()
