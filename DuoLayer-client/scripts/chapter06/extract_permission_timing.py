#!/usr/bin/env python3

import argparse
import re
from datetime import datetime
from pathlib import Path


def timestamp(line):
    match = re.match(r"\[([^]]+)\]", line)
    if not match:
        raise ValueError(f"trace line has no timestamp: {line}")
    value = match.group(1).replace("Z", "+00:00")
    # Go's RFC3339Nano timestamp may carry nine fractional digits, whereas
    # Python's datetime parser accepts microseconds. Six digits retain far
    # more precision than required by the millisecond-level experiment.
    value = re.sub(r"(\.\d{6})\d+(?=[+-]\d{2}:\d{2}$)", r"\1", value)
    return datetime.fromisoformat(value)


def metric(line, pattern, name):
    match = re.search(pattern, line)
    if not match:
        raise ValueError(f"cannot parse {name} from CONTRACT-OUT trace")
    return float(match.group(1))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace", required=True, type=Path)
    args = parser.parse_args()
    lines = args.trace.read_text(encoding="utf-8").splitlines()

    contract_index = next(
        (index for index in range(len(lines) - 1, -1, -1) if "[CONTRACT-OUT]" in lines[index]),
        None,
    )
    if contract_index is None:
        raise SystemExit("CONTRACT-OUT was not recorded; the integrated authorization path did not complete")
    decision_index = next(
        (index for index in range(contract_index, -1, -1) if "[DECISION-IN]" in lines[index]),
        None,
    )
    if decision_index is None:
        raise SystemExit("DECISION-IN was not recorded before CONTRACT-OUT")

    access_index = next(
        (index for index in range(decision_index, -1, -1) if "[AC-IN]" in lines[index]),
        None,
    )
    if access_index is None:
        raise SystemExit("AC-IN was not recorded before DECISION-IN")

    start = timestamp(lines[access_index])
    end = timestamp(lines[contract_index])
    provider_ms = (end - start).total_seconds() * 1000.0
    line = lines[contract_index]
    bundle = metric(line, r"ProofBundleRead\s*:\s*([0-9.]+)\s*ms", "ProofBundleRead")
    chain = metric(line, r"ChainDecision\s*:\s*([0-9.]+)\s*ms", "ChainDecision")
    total = metric(line, r"VerifyTotal\s*:\s*([0-9.]+)\s*ms", "VerifyTotal")
    core = metric(line, r"VerifyCost=([0-9.]+)ms", "VerifyCost")
    print(f"{provider_ms:.9f},{bundle:.9f},{chain:.9f},{total:.9f},{core:.9f}")


if __name__ == "__main__":
    main()
