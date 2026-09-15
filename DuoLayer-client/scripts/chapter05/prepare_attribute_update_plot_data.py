#!/usr/bin/env python3
"""Aggregate Chapter 5 attribute-evolution measurements into plot tables."""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path


PHASES = (
    ("LocalCommitRefresh", "local_commit_ms"),
    ("ChainAttributeUpdate", "chain_update_ms"),
    ("PolyLockKeyGenTotal", "polylock_keygen_ms"),
    ("AttributeUpdateTotal", "total_ms"),
)


def mean_std(values: list[float]) -> tuple[float, float]:
    return statistics.fmean(values), statistics.stdev(values) if len(values) > 1 else 0.0


def load(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise FileNotFoundError(path)
    with path.open(newline="") as handle:
        rows = list(csv.DictReader(handle, delimiter="\t"))
    if not rows:
        raise RuntimeError(f"no measurements in {path}")
    for row in rows:
        stage_sum = sum(float(row[column]) for _, column in PHASES[:3])
        if abs(stage_sum - float(row["total_ms"])) > 0.02:
            raise RuntimeError(f"attribute stage sum mismatch: {row}")
    return rows


def aggregate(rows: list[dict[str, str]], sweep: str) -> list[dict[str, str]]:
    key_name = "AttrNum" if sweep == "N" else "AffectedUsers"
    source_key = "attr_num" if sweep == "N" else "affected_users"
    groups: dict[int, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        if row["sweep"] == sweep:
            groups[int(row[source_key])].append(row)
    if not groups:
        raise RuntimeError(f"missing sweep={sweep} rows")

    output: list[dict[str, str]] = []
    for value, samples in sorted(groups.items()):
        item = {
            key_name: str(value),
            "AttrNum": samples[0]["attr_num"],
            "LegalSpaceSize": str(int(samples[0]["attr_num"]) * 10),
            "AffectedUsers": samples[0]["affected_users"],
            "TargetSigma": samples[0]["sigma"],
            "Runs": str(len(samples)),
        }
        for label, column in PHASES:
            mean, std = mean_std([float(row[column]) for row in samples])
            item[f"{label}MSMean"] = f"{mean:.6f}"
            item[f"{label}MSStd"] = f"{std:.6f}"
        output.append(item)
    return output


def write(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def print_table(title: str, rows: list[dict[str, str]], x_key: str) -> None:
    print(f"\n{title}")
    print(f"{'x':>8} {'Local(ms)':>14} {'Chain(ms)':>14} {'KeyGen(ms)':>14} {'Total(ms)':>14}")
    for row in rows:
        cells = []
        for phase, _ in PHASES:
            cells.append(
                f"{float(row[f'{phase}MSMean']):.3f}±{float(row[f'{phase}MSStd']):.3f}"
            )
        print(f"{row[x_key]:>8} " + " ".join(f"{cell:>14}" for cell in cells))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()

    source = args.input_dir / "attribute_update_measurements.tsv"
    output_dir = args.output_dir or args.input_dir / "plot_data"
    rows = load(source)
    by_attr = aggregate(rows, "N")
    by_users = aggregate(rows, "R")
    attr_csv = output_dir / "attribute_update_by_attr_num.csv"
    users_csv = output_dir / "attribute_update_by_affected_users.csv"
    write(attr_csv, by_attr)
    write(users_csv, by_users)
    print_table("Attribute update by AttrNum", by_attr, "AttrNum")
    print_table("Attribute update by affected users", by_users, "AffectedUsers")
    print(f"\nPlot CSV: {attr_csv}")
    print(f"Plot CSV: {users_csv}")


if __name__ == "__main__":
    main()
